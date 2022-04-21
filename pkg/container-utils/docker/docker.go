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
// and Containerd. For instance, Dockershim does not provide the container pid1
// with the ContainerStatus() call as Containerd and CRI-O do.
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
	containerID, err := runtimeclient.ParseContainerID(Name, containerID)
	if err != nil {
		return -1, err
	}

	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return -1, err
	}

	if containerJSON.State == nil {
		return -1, errors.New("container state is nil")
	}

	if containerJSON.State.Pid == 0 {
		return -1, errors.New("got zero pid")
	}

	return containerJSON.State.Pid, nil
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
			Name:    strings.TrimPrefix(containers[0].Names[0], "/"),
			Running: container.State == "running",
		}
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

	return &runtimeclient.ContainerData{
		ID:      containers[0].ID,
		Name:    strings.TrimPrefix(containers[0].Names[0], "/"),
		Running: containers[0].State == "running",
	}, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}
