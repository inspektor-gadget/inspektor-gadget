// Copyright 2022 The Inspektor Gadget authors
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

package cri

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	runtimeclient "github.com/kinvolk/inspektor-gadget/pkg/container-utils/runtime-client"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

// CRIClient implements the ContainerRuntimeClient interface using the CRI
// plugin interface to communicate with the different container runtimes.
type CRIClient struct {
	Name        string
	SocketPath  string
	ConnTimeout time.Duration

	conn   *grpc.ClientConn
	client pb.RuntimeServiceClient
}

func NewCRIClient(name, socketPath string, timeout time.Duration) (CRIClient, error) {
	conn, err := grpc.Dial(
		socketPath,
		grpc.WithInsecure(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return CRIClient{}, err
	}

	return CRIClient{
		Name:        name,
		SocketPath:  socketPath,
		ConnTimeout: timeout,
		conn:        conn,
		client:      pb.NewRuntimeServiceClient(conn),
	}, nil
}

// parseExtraInfo parses the container extra information returned by
// ContainerStatus(). It keeps backward compatibility after the ContainerInfo
// format was modified in:
// cri-o v1.18.0: https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
// containerd v1.6.0-beta.1: https://github.com/containerd/containerd/commit/85b943eb47bc7abe53b9f9e3d953566ed0f65e6c
func parseExtraInfo(extraInfo map[string]string) (int, error) {
	info, ok := extraInfo["info"]
	if !ok {
		// Try with old format
		pidStr, ok := extraInfo["pid"]
		if !ok {
			return -1, fmt.Errorf("container status reply from runtime doesn't contain pid")
		}

		pid, err := strconv.Atoi(pidStr)
		if err != nil {
			return -1, fmt.Errorf("failed to parse pid %q: %w", pidStr, err)
		}
		if pid == 0 {
			return -1, fmt.Errorf("got zero pid")
		}

		return pid, nil
	}

	type InfoContent struct {
		Pid int `json:"pid"`
	}

	var infoContent InfoContent
	err := json.Unmarshal([]byte(info), &infoContent)
	if err != nil {
		return -1, fmt.Errorf("failed extracting pid from container status reply: %w", err)
	}
	if infoContent.Pid == 0 {
		return -1, fmt.Errorf("got zero pid")
	}

	return infoContent.Pid, nil
}

func (c *CRIClient) PidFromContainerID(containerID string) (int, error) {
	containerID, err := runtimeclient.ParseContainerID(c.Name, containerID)
	if err != nil {
		return -1, err
	}

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return -1, err
	}

	return parseExtraInfo(res.Info)
}

func listContainers(c *CRIClient, filter *pb.ContainerFilter) ([]*pb.Container, error) {
	request := &pb.ListContainersRequest{}
	if filter != nil {
		request.Filter = filter
	}

	res, err := c.client.ListContainers(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("failed to list containers with request %+v: %w",
			request, err)
	}

	return res.GetContainers(), nil
}

func (c *CRIClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*runtimeclient.ContainerData, len(containers))

	for i, container := range containers {
		ret[i] = CRIContainerToContainerData(c.Name, container)
	}

	return ret, nil
}

func (c *CRIClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	containers, err := listContainers(c, &pb.ContainerFilter{
		Id: containerID,
	})
	if err != nil {
		return nil, err
	}

	if len(containers) == 0 {
		return nil, fmt.Errorf("container %q not found", containerID)
	}
	if len(containers) > 1 {
		log.Warnf("CRIClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}

	return CRIContainerToContainerData(c.Name, containers[0]), nil
}

func CRIContainerToContainerData(runtimeName string, container *pb.Container) *runtimeclient.ContainerData {
	return &runtimeclient.ContainerData{
		ID:      container.Id,
		Name:    strings.TrimPrefix(container.GetMetadata().Name, "/"),
		Running: container.GetState() == pb.ContainerState_CONTAINER_RUNNING,
		Runtime: runtimeName,
	}
}

func (c *CRIClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}
