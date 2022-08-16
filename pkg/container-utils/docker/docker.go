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

	log "github.com/sirupsen/logrus"

	dockertypes "github.com/docker/docker/api/types"
	dockerfilters "github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/client"
	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
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

func (c *DockerClient) PidFromContainerID(containerID string) (int, error) {
	// Get the container extended data (containing the PID)
	containerExtendedData, err := c.GetContainerExtended(containerID)
	if err != nil {
		return -1, err
	}

	return containerExtendedData.Pid, nil
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

func (c *DockerClient) GetContainerExtended(containerID string) (*runtimeclient.ContainerExtendedData, error) {

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
	if containerJSON.HostConfig == nil {
		return nil, errors.New("container host config is nil")
	}

	containerExtendedData := runtimeclient.ContainerExtendedData {
		ContainerData: runtimeclient.ContainerData {
			ID:      containerJSON.ID,
			Name:    strings.TrimPrefix(containerJSON.Name, "/"),
			Running: containerJSON.State.Status == "running",
			Runtime: Name,
		},
		Pid: containerJSON.State.Pid,
		State: containerStatusStateToRuntimeClientState(containerJSON.State),
		CgroupsPath: string(containerJSON.HostConfig.Cgroup),
	}
	containerExtendedData.Mounts = []runtimeclient.ContainerMountData{}
	for _, containerMount := range containerJSON.Mounts {
		containerExtendedData.Mounts = append(containerExtendedData.Mounts, runtimeclient.ContainerMountData{
			Destination: containerMount.Destination,
			Source: containerMount.Source,
		})
	}

	if containerExtendedData.Pid == 0 {
		return nil, errors.New("got zero pid")
	}

	return &containerExtendedData, nil
}

func DockerContainerToContainerData(container *dockertypes.Container) *runtimeclient.ContainerData {
	return &runtimeclient.ContainerData{
		ID:      container.ID,
		Name:    strings.TrimPrefix(container.Names[0], "/"),
		Running: container.State == "running",
		Runtime: Name,
	}
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerState *dockertypes.ContainerState) (runtimeClientState string) {
	switch containerState.Status {
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
