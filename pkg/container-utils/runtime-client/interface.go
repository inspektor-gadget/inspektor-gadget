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

package runtimeclient

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1alpha2"
)

type ContainerData struct {
	// ID is the container ID without the container runtime prefix. For
	// instance, "cri-o://" for CRI-O.
	ID string

	// Name is the container name. In the case the container runtime response
	// with multiples, Name contains only the first element.
	Name string

	// Running defines whether or not the container is in the running state
	Running bool

	// Runtime is the name of the runtime (e.g. docker, cri-o, containerd). It
	// is useful to distinguish who is the "owner" of each container in a list
	// of containers collected from multiples runtimes.
	Runtime string
}

// ContainerRuntimeClient defines the interface to communicate with the
// different container runtimes.
type ContainerRuntimeClient interface {
	// PidFromContainerID returns the pid1 of the container identified by the
	// specified ID. In case of errors, it returns -1 and an error describing
	// what happened.
	PidFromContainerID(containerID string) (int, error)

	// GetContainers returns a slice with the information of all the containers.
	GetContainers() ([]*ContainerData, error)

	// GetContainers returns the information of the container identified by the
	// provided ID.
	GetContainer(containerID string) (*ContainerData, error)

	// Close tears down the connection with the container runtime.
	Close() error
}

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
		grpc.WithDialer(func(addr string, timeout time.Duration) (net.Conn, error) {
			return net.DialTimeout("unix", socketPath, timeout)
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

func ParseContainerID(expectedRuntime, containerID string) (string, error) {
	// If ID contains a prefix, it must match the format "<runtime>://<ID>"
	split := strings.SplitN(containerID, "://", 2)
	if len(split) == 2 {
		if split[0] != expectedRuntime {
			return "", fmt.Errorf("invalid container runtime %q, it should be %q",
				containerID, expectedRuntime)
		}
		return split[1], nil
	}

	return split[0], nil
}

func (c *CRIClient) PidFromContainerID(containerID string) (int, error) {
	containerID, err := ParseContainerID(c.Name, containerID)
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

func (c *CRIClient) GetContainers() ([]*ContainerData, error) {
	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	ret := make([]*ContainerData, len(containers))

	for i, container := range containers {
		ret[i] = CRIContainerToContainerData(c.Name, container)
	}

	return ret, nil
}

func (c *CRIClient) GetContainer(containerID string) (*ContainerData, error) {
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

func CRIContainerToContainerData(runtimeName string, container *pb.Container) *ContainerData {
	return &ContainerData{
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
