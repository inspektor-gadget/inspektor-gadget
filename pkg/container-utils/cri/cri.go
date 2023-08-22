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

	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	runtime "k8s.io/cri-api/pkg/apis/runtime/v1"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// CRIClient implements the ContainerRuntimeClient interface using the CRI
// plugin interface to communicate with the different container runtimes.
type CRIClient struct {
	Name        types.RuntimeName
	SocketPath  string
	ConnTimeout time.Duration

	conn   *grpc.ClientConn
	client runtime.RuntimeServiceClient
}

func NewCRIClient(name types.RuntimeName, socketPath string, timeout time.Duration) (CRIClient, error) {
	conn, err := grpc.Dial(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return CRIClient{}, err
	}

	cc := CRIClient{
		Name:        name,
		SocketPath:  socketPath,
		ConnTimeout: timeout,
		conn:        conn,
		client:      runtime.NewRuntimeServiceClient(conn),
	}

	return cc, nil
}

func listContainers(c *CRIClient, filter *runtime.ContainerFilter) ([]*runtime.Container, error) {
	request := &runtime.ListContainersRequest{}
	if filter != nil {
		request.Filter = filter
	}

	res, err := c.client.ListContainers(context.Background(), request)
	if err != nil {
		return nil, fmt.Errorf("listing containers with request %+v: %w",
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
	containers, err := listContainers(c, &runtime.ContainerFilter{
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

func (c *CRIClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	containerID, err := runtimeclient.ParseContainerID(c.Name, containerID)
	if err != nil {
		return nil, err
	}

	request := &runtime.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := c.client.ContainerStatus(context.Background(), request)
	if err != nil {
		return nil, err
	}

	return parseContainerDetailsData(c.Name, res.Status, res.Info)
}

func (c *CRIClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}

	return nil
}

// parseContainerDetailsData parses the container status and extra information
// returned by ContainerStatus() into a ContainerDetailsData structure.
func parseContainerDetailsData(runtimeName types.RuntimeName, containerStatus CRIContainer,
	extraInfo map[string]string,
) (*runtimeclient.ContainerDetailsData, error) {
	// Create container details structure to be filled.
	containerDetailsData := &runtimeclient.ContainerDetailsData{
		ContainerData: *CRIContainerToContainerData(runtimeName, containerStatus),
	}

	// Parse the extra info and fill the data.
	err := parseExtraInfo(extraInfo, containerDetailsData)
	if err != nil {
		return nil, err
	}

	return containerDetailsData, nil
}

// parseExtraInfo parses the extra information returned by ContainerStatus()
// into a ContainerDetailsData structure. It keeps backward compatibility after
// the ContainerInfo format was modified in:
// cri-o v1.18.0: https://github.com/cri-o/cri-o/commit/be8e876cdabec4e055820502fed227aa44971ddc
// containerd v1.6.0-beta.1: https://github.com/containerd/containerd/commit/85b943eb47bc7abe53b9f9e3d953566ed0f65e6c
// NOTE: CRI-O does not have runtime spec prior to 1.18.0
func parseExtraInfo(extraInfo map[string]string,
	containerDetailsData *runtimeclient.ContainerDetailsData,
) error {
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
	pid := -1
	containerDetailsData.Pid = pid

	// Get the extra info from the map.
	var runtimeSpec *RuntimeSpecContent
	info, ok := extraInfo["info"]
	if ok {
		// Unmarshal the JSON to fields.
		var infoContent InfoContent
		err := json.Unmarshal([]byte(info), &infoContent)
		if err != nil {
			return fmt.Errorf("extracting pid from container status reply: %w", err)
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
			return fmt.Errorf("container status reply from runtime doesn't contain pid")
		}
		var err error
		pid, err = strconv.Atoi(pidStr)
		if err != nil {
			return fmt.Errorf("parsing pid %q: %w", pidStr, err)
		}

		// Extract the runtime spec (may not exist).
		runtimeSpecStr, ok := extraInfo["runtimeSpec"]
		if ok {
			// Unmarshal the JSON to fields.
			runtimeSpec = &RuntimeSpecContent{}
			err := json.Unmarshal([]byte(runtimeSpecStr), runtimeSpec)
			if err != nil {
				return fmt.Errorf("extracting runtime spec from container status reply: %w", err)
			}
		}
	}

	// Validate extracted fields.
	if pid == 0 {
		return fmt.Errorf("got zero pid")
	}

	// Set the PID value.
	containerDetailsData.Pid = pid

	// Copy the runtime spec fields.
	if runtimeSpec != nil {
		if runtimeSpec.Linux != nil {
			containerDetailsData.CgroupsPath = runtimeSpec.Linux.CgroupsPath
		}
		if len(runtimeSpec.Mounts) > 0 {
			containerDetailsData.Mounts = make([]runtimeclient.ContainerMountData, len(runtimeSpec.Mounts))
			for i, specMount := range runtimeSpec.Mounts {
				containerDetailsData.Mounts[i] = runtimeclient.ContainerMountData{
					Destination: specMount.Destination,
					Source:      specMount.Source,
				}
			}
		}
	}

	return nil
}

// Convert the state from container status to state of runtime client.
func containerStatusStateToRuntimeClientState(containerStatusState runtime.ContainerState) (runtimeClientState string) {
	switch containerStatusState {
	case runtime.ContainerState_CONTAINER_CREATED:
		runtimeClientState = runtimeclient.StateCreated
	case runtime.ContainerState_CONTAINER_RUNNING:
		runtimeClientState = runtimeclient.StateRunning
	case runtime.ContainerState_CONTAINER_EXITED:
		runtimeClientState = runtimeclient.StateExited
	case runtime.ContainerState_CONTAINER_UNKNOWN:
		runtimeClientState = runtimeclient.StateUnknown
	default:
		runtimeClientState = runtimeclient.StateUnknown
	}
	return
}

// CRIContainer is an interface that contains the methods required to get
// the information of a container from the responses of the CRI. In particular,
// from runtime.ContainerStatus and runtime.Container.
type CRIContainer interface {
	GetId() string
	GetState() runtime.ContainerState
	GetMetadata() *runtime.ContainerMetadata
	GetLabels() map[string]string
	GetImage() *runtime.ImageSpec
	GetImageRef() string
}

func CRIContainerToContainerData(runtimeName types.RuntimeName, container CRIContainer) *runtimeclient.ContainerData {
	containerMetadata := container.GetMetadata()
	image := container.GetImage()
	// for crio imageRef has the following structure:
	// k8s.gcr.io/kube-apiserver@sha256:4a165184c779c0a4f2d31d6676b7790589b977c3c8fbc0577dac2544fd69cade
	// the hash being the image digest
	imageRef := container.GetImageRef()

	containerData := &runtimeclient.ContainerData{
		Runtime: runtimeclient.RuntimeContainerData{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerID:          container.GetId(),
				ContainerName:        strings.TrimPrefix(containerMetadata.GetName(), "/"),
				RuntimeName:          runtimeName,
				ContainerImageName:   image.GetImage(),
				ContainerImageDigest: strings.Split(imageRef, "@")[1],
			},
			State: containerStatusStateToRuntimeClientState(container.GetState()),
		},
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(containerData, container.GetLabels())

	// CRI-O does not use the same container name of Kubernetes as containerd.
	// Instead, it uses a composed name as Docker does, but such name is not
	// available in the container metadata.
	if runtimeName == types.RuntimeNameCrio {
		containerData.Runtime.ContainerName = fmt.Sprintf("k8s_%s_%s_%s_%s_%d",
			containerData.K8s.ContainerName,
			containerData.K8s.PodName,
			containerData.K8s.Namespace,
			containerData.K8s.PodUID,
			containerMetadata.GetAttempt())
	}

	return containerData
}
