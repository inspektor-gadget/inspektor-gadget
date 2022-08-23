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

	dockertypes "github.com/docker/docker/api/types"
	dockerfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	cgroups "github.com/kinvolk/inspektor-gadget/pkg/container-utils/cgroups"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
	log "github.com/sirupsen/logrus"
)

const (
	Name              = "docker"
	DefaultSocketPath = "/run/docker.sock"
	DefaultTimeout    = 2 * time.Second
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

func NewDockerClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = DefaultSocketPath
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

func listContainers(c *DockerClient, filter *dockerfilters.Args) ([]dockertypes.Container, error) {
	opts := dockertypes.ContainerListOptions{
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
		return nil, fmt.Errorf("failed to list containers with options %+v: %w",
			opts, err)
	}

	return containers, nil
}

func (c *DockerClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, len(containers))

	for i, container := range containers {
		ret[i] = &runtimeclient.ContainerData{
			ID:      container.ID,
			Name:    strings.TrimPrefix(container.Names[0], "/"),
			State:   containerStatusStateToRuntimeClientState(container.State),
			Runtime: Name,
		}
	}

	return ret, nil
}

func (c *DockerClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	containerID, err := runtimeclient.ParseContainerID(Name, containerID)
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
	if containerJSON.HostConfig == nil {
		return nil, errors.New("container host config is nil")
	}
	containerData := runtimeclient.ContainerData{
		ID:      containerJSON.ID,
		Name:    strings.TrimPrefix(containerJSON.Name, "/"),
		State:   containerStatusStateToRuntimeClientState(containerJSON.State.Status),
		Runtime: Name,
	}

	containerExtraInfo := runtimeclient.ContainerExtraInfo{
		Pid:         containerJSON.State.Pid,
		CgroupsPath: string(containerJSON.HostConfig.Cgroup),
	}
	if len(containerJSON.Mounts) > 0 {
		containerExtraInfo.Mounts = make([]runtimeclient.ContainerMountData, len(containerJSON.Mounts))
		for i, containerMount := range containerJSON.Mounts {
			containerExtraInfo.Mounts[i] = runtimeclient.ContainerMountData{
				Destination: containerMount.Destination,
				Source:      containerMount.Source,
			}
		}
	}

	// Try to get cgroups information from /proc/<pid>/cgroup as a fallback.
	// However, don't fail if such a file is not available, as it would prevent the
	// whole feature to work on systems without this file.
	if containerExtraInfo.CgroupsPath == "" {
		log.Debugf("cgroups info not available on Docker for container %s. Trying /proc/%d/cgroup as a fallback",
			containerID, containerExtraInfo.Pid)

		// Get cgroup paths for V1 and V2.
		cgroupPathV1, cgroupPathV2, err := cgroups.GetCgroupPaths(containerExtraInfo.Pid)
		if err == nil {
			cgroupsPath := cgroupPathV1
			if cgroupsPath == "" {
				cgroupsPath = cgroupPathV2
			}
			containerExtraInfo.CgroupsPath = cgroupsPath
		} else {
			log.Warnf("failed to get cgroups info of container %s from /proc/%d/cgroup: %s",
				containerID, containerExtraInfo.Pid, err)
		}
	}

	// Set the extra info of the container.
	containerData.ExtraInfo = &containerExtraInfo

	return &containerData, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
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
