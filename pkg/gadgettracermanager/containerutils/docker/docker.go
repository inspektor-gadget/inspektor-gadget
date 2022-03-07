// Copyright 2019-2021 The Inspektor Gadget authors
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
	"net"
	"strings"
	"time"

	"github.com/docker/docker/client"
)

const (
	DefaultSocketPath = "/run/docker.sock"
	DefaultTimeout    = 2 * time.Second
)

type DockerClient struct {
	client *client.Client
}

func NewDockerClient(path string) (*DockerClient, error) {
	cli, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.WithDialContext(func(ctx context.Context, network, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", path, DefaultTimeout)
		}),
	)
	if err != nil {
		return nil, err
	}

	return &DockerClient{
		client: cli,
	}, nil
}

func (c *DockerClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}

	return nil
}

func (c *DockerClient) PidFromContainerID(containerID string) (int, error) {
	if !strings.HasPrefix(containerID, "docker://") {
		return -1, fmt.Errorf("invalid CRI %s, it should be docker", containerID)
	}

	containerID = strings.TrimPrefix(containerID, "docker://")

	containerJSON, err := c.client.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return -1, err
	}

	if containerJSON.State == nil {
		return -1, errors.New("container state is nil")
	}

	return containerJSON.State.Pid, nil
}
