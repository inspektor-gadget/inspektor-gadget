// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package docker

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/docker/docker/api/types/container"
	dockerfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cgroups"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/cri"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	DefaultTimeout = 2 * time.Second
)

// DockerClient implements the ContainerRuntimeClient interface but using the
// Docker Engine API instead of the CRI plugin interface (Dockershim). It was
// necessary because Dockershim does not always use the same approach of CRI-O
// and containerd. For instance, Dockershim does not provide the container pid1
// with the ContainerStatus() call as containerd and CRI-O do.
type DockerClient struct {
	client     *client.Client
	socketPath string
}

func NewDockerClient(socketPath string, protocol string) (runtimeclient.ContainerRuntimeClient, error) {
	switch protocol {
	// Empty string falls back to "internal". Used by unit tests.
	case "", containerutilsTypes.RuntimeProtocolInternal:
		// handled below

	case containerutilsTypes.RuntimeProtocolCRI:
		// TODO: Configurable
		joinedSocketPath, err := securejoin.SecureJoin(host.HostRoot, runtimeclient.CriDockerDefaultSocketPath)
		if err != nil {
			return nil, fmt.Errorf("securejoining %v to %v: %w", host.HostRoot, runtimeclient.CriDockerDefaultSocketPath, err)
		}
		return cri.NewCRIClient(types.RuntimeNameDocker, joinedSocketPath, DefaultTimeout)

	default:
		return nil, fmt.Errorf("unknown runtime protocol %q", protocol)
	}

	if socketPath == "" {
		socketPath = runtimeclient.DockerDefaultSocketPath
	}

	cli, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.WithHost("unix://"+socketPath),
		client.WithTimeout(DefaultTimeout),
	)
	if err != nil {
		return nil, err
	}

	return &DockerClient{
		client:     cli,
		socketPath: socketPath,
	}, nil
}

func listContainers(c *DockerClient, filter *dockerfilters.Args) ([]container.Summary, error) {
	opts := container.ListOptions{
		// We need to request for all containers (also non-running) because
		// when we are enriching a container that is being created, it is
		// not in "running" state yet.
		All: true,
	}
	if filter != nil {
		opts.Filters = *filter
	}

	containers, err := c.client.ContainerList(context.Background(), opts)
	if err != nil {
		return nil, fmt.Errorf("listing containers with options %+v: %w",
			opts, err)
	}

	// Temporarily drop pod sandbox containers. Otherwise, they will be
	// considered as normal containers and EnrichByNetNs will incorrectly think
	// that they are using a given network namespace. See issue
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/1095.
	noPauseContainers := []container.Summary{}
	for _, c := range containers {
		if c.Labels["io.kubernetes.docker.type"] == "podsandbox" {
			continue
		}
		noPauseContainers = append(noPauseContainers, c)
	}
	if filter != nil && len(containers) != 0 && len(noPauseContainers) == 0 {
		return nil, runtimeclient.ErrPauseContainer
	}

	return noPauseContainers, nil
}

func (c *DockerClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, len(containers))

	for i, container := range containers {
		ret[i] = DockerContainerToContainerData(&container)
	}

	return ret, nil
}

func (c *DockerClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	filter := dockerfilters.NewArgs()
	filter.Add("id", containerID)

	containers, err := listContainers(c, &filter)
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(containers) > 1 {
		log.Warnf("DockerClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}

	return DockerContainerToContainerData(&containers[0]), nil
}

func (c *DockerClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	containerID, err := runtimeclient.ParseContainerID(types.RuntimeNameDocker, containerID)
	if err != nil {
		return nil, err
	}

	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return nil, err
	}

	if containerJSON.State == nil {
		return nil, errors.New("container state is nil")
	}
	if containerJSON.State.Pid == 0 {
		return nil, errors.New("got zero pid")
	}
	if containerJSON.Config == nil {
		return nil, errors.New("container config is nil")
	}
	if containerJSON.HostConfig == nil {
		return nil, errors.New("container host config is nil")
	}

	containerData := buildContainerData(
		containerJSON.ID,
		containerJSON.Name,
		containerJSON.Config.Image,
		c.getContainerImageDigest(containerJSON.Image),
		containerJSON.State.Status,
		containerJSON.Config.Labels)

	containerDetailsData := runtimeclient.ContainerDetailsData{
		ContainerData: *containerData,
		Pid:           containerJSON.State.Pid,
		CgroupsPath:   string(containerJSON.HostConfig.Cgroup),
	}
	if len(containerJSON.Mounts) > 0 {
		containerDetailsData.Mounts = make([]runtimeclient.ContainerMountData, len(containerJSON.Mounts))
		for i, containerMount := range containerJSON.Mounts {
			containerDetailsData.Mounts[i] = runtimeclient.ContainerMountData{
				Destination: containerMount.Destination,
				Source:      containerMount.Source,
			}
		}
	}

	// Try to get cgroups information from /proc/<pid>/cgroup as a fallback.
	// However, don't fail if such a file is not available, as it would prevent the
	// whole feature to work on systems without this file.
	if containerDetailsData.CgroupsPath == "" {
		log.Debugf("cgroups info not available on Docker for container %s. Trying /proc/%d/cgroup as a fallback",
			containerID, containerDetailsData.Pid)

		// Get cgroup paths for V1 and V2.
		cgroupPathV1, cgroupPathV2, err := cgroups.GetCgroupPaths(containerDetailsData.Pid)
		if err == nil {
			cgroupsPath := cgroupPathV1
			if cgroupsPath == "" {
				cgroupsPath = cgroupPathV2
			}
			containerDetailsData.CgroupsPath = cgroupsPath
		} else {
			log.Warnf("failed to get cgroups info of container %s from /proc/%d/cgroup: %s",
				containerID, containerDetailsData.Pid, err)
		}
	}

	return &containerDetailsData, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

// Gets the image digest for the given image ID, if the digest exists.
// The digest is usually only available if the image was either pulled from a registry, or if the image was pushed to a registry, which is when the manifest is generated and its digest calculated.
// Note: This function only works for already running containers and not for containers that are being created.
func (c *DockerClient) getContainerImageDigest(imageId string) string {
	imageInspect, err := c.client.ImageInspect(context.Background(), imageId)
	if err != nil {
		log.Warnf("Failed to get image digest for image %s: %s", imageId, err)
		return ""
	}

	if len(imageInspect.RepoDigests) == 0 {
		log.Warnf("No digest found for image %s", imageId)
		return ""
	}

	imageAndDigest := strings.Split(imageInspect.RepoDigests[0], "@")
	if len(imageAndDigest) < 2 {
		log.Warnf("Digest is in wrong format for image %s", imageId)
		return ""
	}

	return imageAndDigest[1]
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerState string) (runtimeClientState string) {
	switch containerState {
	case "created":
		runtimeClientState = runtimeclient.StateCreated
	case "running":
		runtimeClientState = runtimeclient.StateRunning
	case "exited":
		runtimeClientState = runtimeclient.StateExited
	case "dead":
		runtimeClientState = runtimeclient.StateExited
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}

func DockerContainerToContainerData(container *container.Summary) *runtimeclient.ContainerData {
	imageDigest := ""
	return buildContainerData(
		container.ID,
		container.Names[0],
		container.Image,
		imageDigest,
		container.State,
		container.Labels)
}

// getContainerImageNamefromImage is a helper to parse the image string we get from Docker API
// and retrieve the image name if provided.
func getContainerImageNamefromImage(image string) string {
	// Image filed provided by Docker API may looks like e.g.
	// 1. gcr.io/k8s-minikube/kicbase:v0.0.37@sha256:8bf7a0e8a062bc5e2b71d28b35bfa9cc862d9220e234e86176b3785f685d8b15
	// OR
	// 2. busybox@sha256:3fbc632167424a6d997e74f52b878d7cc478225cffac6bc977eedfe51c7f4e79
	// These two provide both image name and digest separated by '@'.
	//
	// 3. docker.io/library/busybox:latest or simply busybox
	// Just image name is provided.
	//
	// 4. sha256:aebe758cef4cd05b9f8cee39758227714d02f42ef3088023c1e3cd454f927a2b
	// This fourth option provides the imageID and, following Docker example, we'll use the imageID.

	// Case 1 or 2
	if strings.Contains(image, "@") {
		return strings.Split(image, "@")[0]
	}

	// Case 3 or 4
	return image
}

// `buildContainerData` takes in basic metadata about a Docker container and
// constructs a `runtimeclient.ContainerData` struct with this information. I also
// enriches containers with the data and returns a pointer the created struct.
func buildContainerData(containerID string, containerName string, containerImage string, containerImageDigest string, state string, labels map[string]string) *runtimeclient.ContainerData {
	containerData := runtimeclient.ContainerData{
		Runtime: runtimeclient.RuntimeContainerData{
			ContainerID:          containerID,
			ContainerName:        strings.TrimPrefix(containerName, "/"),
			RuntimeName:          types.RuntimeNameDocker,
			ContainerImageName:   getContainerImageNamefromImage(containerImage),
			ContainerImageDigest: containerImageDigest,
			State:                containerStatusStateToRuntimeClientState(state),
		},
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(&containerData, labels)

	return &containerData
}
