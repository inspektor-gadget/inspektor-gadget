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

package containerd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

const (
	DEFAULT_SOCKET_PATH = "/run/containerd/containerd.sock"
	DEFAULT_TIMEOUT     = 2 * time.Second
)

type ContainerdClient struct {
	conn   *grpc.ClientConn
	client pb.RuntimeServiceClient
}

func NewContainerdClient(path string) (*ContainerdClient, error) {
	conn, err := grpc.Dial(
		path,
		grpc.WithInsecure(),
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", path, DEFAULT_TIMEOUT)
		}),
	)
	if err != nil {
		return nil, err
	}

	client := pb.NewRuntimeServiceClient(conn)
	return &ContainerdClient{
		conn:   conn,
		client: client,
	}, nil
}

func (c *ContainerdClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func (c *ContainerdClient) PidFromContainerId(containerID string) (int, error) {
	if !strings.HasPrefix(containerID, "containerd://") {
		return -1, fmt.Errorf("Invalid CRI %s, it should be containerd", containerID)
	}

	containerID = strings.TrimPrefix(containerID, "containerd://")

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	status, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return -1, err
	}

	info, ok := status.Info["info"]
	if !ok {
		return -1, fmt.Errorf("container status reply from runtime doesn't contain 'info'")
	}

	containerdInspect := struct{ Pid int }{}
	if err := json.Unmarshal([]byte(info), &containerdInspect); err != nil {
		return -1, err
	}

	return containerdInspect.Pid, nil
}
