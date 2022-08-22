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
	containerID, err := runtimeclient.ParseContainerID(c.Name, containerID)
	if err != nil {
		return nil, err
	}

	request := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return nil, err
	}

	return parseContainerData(c.Name, res.Status, res.Info)
}

func (c *CRIClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

func CRIContainerToContainerData(runtimeName string, container *pb.Container) *runtimeclient.ContainerData {
	return &runtimeclient.ContainerData{
		ID:      container.Id,
		Name:    strings.TrimPrefix(container.GetMetadata().Name, "/"),
		State:   containerStatusStateToRuntimeClientState(container.GetState()),
		Runtime: runtimeName,
	}
}

// parseContainerData parses the container status and extra information
// returned by ContainerStatus() into a ContainerExtraInfo structure.
func parseContainerData(runtimeName string, containerStatus *pb.ContainerStatus,
	extraInfo map[string]string,
) (*runtimeclient.ContainerData, error) {
	// Create container extra info structure to be filled.
	containerData := runtimeclient.ContainerData{
		ID:      containerStatus.Id,
		Name:    strings.TrimPrefix(containerStatus.GetMetadata().Name, "/"),
		State:   containerStatusStateToRuntimeClientState(containerStatus.State),
		Runtime: runtimeName,
	}

	// Parse the extra info and fill the data.
	containerExtraInfo, err := parseExtraInfo(extraInfo)
	if err != nil {
		return nil, err
	}
	containerData.ExtraInfo = containerExtraInfo

	return &containerData, nil
}

// parseExtraInfo parses the extra information returned by ContainerStatus()
// into a ContainerExtraInfo structure. It keeps backward compatibility after
// the ContainerInfo format was modified in:
// cri-o v1.18.0: https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
// containerd v1.6.0-beta.1: https://github.com/containerd/containerd/commit/85b943eb47bc7abe53b9f9e3d953566ed0f65e6c
// NOTE: CRI-O does not have runtime spec prior to 1.18.0
func parseExtraInfo(extraInfo map[string]string) (*runtimeclient.ContainerExtraInfo, error) {
	// Define the info content (only required fields).
	type RuntimeSpecContent struct {
		Mounts []struct {
			Destination string `json:"destination"`
			Source      string `json:"source,omitempty"`
		} `json:"mounts,omitempty"`
		Linux *struct {
			CgroupsPath string `json:"cgroupsPath,omitempty"`
		} `json:"linux,omitempty" platform:"linux"`
	}
	type InfoContent struct {
		Pid         int                `json:"pid"`
		RuntimeSpec RuntimeSpecContent `json:"runtimeSpec"`
	}

	// Set invalid value to PID.
	containerExtraInfo := runtimeclient.ContainerExtraInfo{}
	pid := -1
	containerExtraInfo.Pid = pid

	// Get the extra info from the map.
	var runtimeSpec *RuntimeSpecContent
	info, ok := extraInfo["info"]
	if ok {

		// Unmarshal the JSON to fields.
		var infoContent InfoContent
		err := json.Unmarshal([]byte(info), &infoContent)
		if err != nil {
			return nil, fmt.Errorf("failed extracting pid from container status reply: %w", err)
		}

		// Set the PID value.
		pid = infoContent.Pid

		// Set the runtime spec pointer, to be copied below.
		runtimeSpec = &infoContent.RuntimeSpec

		// Legacy parsing.
	} else {
		// Extract the PID.
		pidStr, ok := extraInfo["pid"]
		if !ok {
			return nil, fmt.Errorf("container status reply from runtime doesn't contain pid")
		}
		var err error
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse pid %q: %w", pidStr, err)
		}

		// Extract the runtime spec (may not exist).
		runtimeSpecStr, ok := extraInfo["runtimeSpec"]
		if ok {
			// Unmarshal the JSON to fields.
			runtimeSpec = &RuntimeSpecContent{}
			err := json.Unmarshal([]byte(runtimeSpecStr), runtimeSpec)
			if err != nil {
				return nil, fmt.Errorf("failed extracting runtime spec from container status reply: %w", err)
			}
		}
	}

	// Validate extracted fields.
	if pid == 0 {
		return nil, fmt.Errorf("got zero pid")
	}

	// Set the PID value.
	containerExtraInfo.Pid = pid

	// Copy the runtime spec fields.
	if runtimeSpec != nil {
		if runtimeSpec.Linux != nil {
			containerExtraInfo.CgroupsPath = runtimeSpec.Linux.CgroupsPath
		}
		containerExtraInfo.Mounts = []runtimeclient.ContainerMountData{}
		for _, specMount := range runtimeSpec.Mounts {
			containerExtraInfo.Mounts = append(containerExtraInfo.Mounts, runtimeclient.ContainerMountData{
				Destination: specMount.Destination,
				Source:      specMount.Source,
			})
		}
	}

	return &containerExtraInfo, nil
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerStatusState pb.ContainerState) (runtimeClientState string) {
	switch containerStatusState {
	case pb.ContainerState_CONTAINER_CREATED:
		runtimeClientState = runtimeclient.StateCreated
	case pb.ContainerState_CONTAINER_RUNNING:
		runtimeClientState = runtimeclient.StateRunning
	case pb.ContainerState_CONTAINER_EXITED:
		runtimeClientState = runtimeclient.StateExited
	case pb.ContainerState_CONTAINER_UNKNOWN:
		runtimeClientState = runtimeclient.StateUnknown
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}
