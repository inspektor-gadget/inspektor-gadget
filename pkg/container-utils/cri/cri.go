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

// podLabelFilter is a set of labels that are used to filter out pod sandbox labels
// that are not user given K8s labels of the pod
var podLabelFilter = map[string]struct{}{
	runtimeclient.ContainerLabelK8sContainerName: {},
	runtimeclient.ContainerLabelK8sPodName:       {},
	runtimeclient.ContainerLabelK8sPodNamespace:  {},
	runtimeclient.ContainerLabelK8sPodUID:        {},
}

// CRIClient implements the ContainerRuntimeClient interface using the CRI
// plugin interface to communicate with the different container runtimes.
type CRIClient struct {
	Name        types.RuntimeName
	SocketPath  string
	ConnTimeout time.Duration

	conn   *grpc.ClientConn
	client runtime.RuntimeServiceClient
}

func NewCRIClient(name types.RuntimeName, socketPath string, timeout time.Duration) (*CRIClient, error) {
	//nolint:staticcheck
	conn, err := grpc.Dial(
		socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			d := net.Dialer{Timeout: timeout}
			return d.DialContext(ctx, "unix", socketPath)
		}),
	)
	if err != nil {
		return nil, err
	}

	return &CRIClient{
		Name:        name,
		SocketPath:  socketPath,
		ConnTimeout: timeout,
		conn:        conn,
		client:      runtime.NewRuntimeServiceClient(conn),
	}, nil
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

func listPodSandboxes(c *CRIClient, filter *runtime.PodSandboxFilter) ([]*runtime.PodSandbox, error) {
	podRequest := &runtime.ListPodSandboxRequest{
		Filter: filter,
	}

	podRes, err := c.client.ListPodSandbox(context.Background(), podRequest)
	if err != nil {
		return nil, fmt.Errorf("listing pod sandboxes with request %+v: %w", podRequest, err)
	}

	return podRes.Items, nil
}

func getPodSandbox(c *CRIClient, podSandboxID string) (*runtime.PodSandbox, error) {
	podSandboxes, err := listPodSandboxes(c, &runtime.PodSandboxFilter{
		Id: podSandboxID,
	})
	if err != nil {
		return nil, err
	}

	if len(podSandboxes) == 0 {
		return nil, fmt.Errorf("pod sandbox %q not found", podSandboxID)
	}
	if len(podSandboxes) > 1 {
		log.Errorf("CRIClient: found multiple pod sandboxes (%d) with ID %q. Taking the first one: %+v",
			len(podSandboxes), podSandboxID, podSandboxes)
	}
	return podSandboxes[0], nil
}

func (c *CRIClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := listContainers(c, nil)
	if err != nil {
		return nil, err
	}

	podSandboxes, err := listPodSandboxes(c, nil)
	if err != nil {
		return nil, err
	}
	podSandboxesMap := make(map[string]*runtime.PodSandbox, len(podSandboxes))
	for _, podSandbox := range podSandboxes {
		podSandboxesMap[podSandbox.Id] = podSandbox
	}

	ret := make([]*runtimeclient.ContainerData, len(containers))

	for i, container := range containers {
		podSandbox, ok := podSandboxesMap[container.PodSandboxId]
		if !ok {
			return nil, fmt.Errorf("pod sandbox %q not found for container %q", container.PodSandboxId, container.Id)
		}
		ret[i] = buildContainerData(c.Name, container, podSandbox)
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
		// Test if the containerID belongs to a pause container
		_, err := getPodSandbox(c, containerID)
		if err != nil {
			// It is not a pause container or we got an error
			return nil, fmt.Errorf("container %q not found", containerID)
		}
		return nil, runtimeclient.ErrPauseContainer
	}
	if len(containers) > 1 {
		log.Errorf("CRIClient: multiple containers (%d) with ID %q. Taking the first one: %+v",
			len(containers), containerID, containers)
	}

	podSandbox, err := getPodSandbox(c, containers[0].PodSandboxId)
	if err != nil {
		return nil, err
	}

	containerData := buildContainerData(c.Name, containers[0], podSandbox)
	return containerData, nil
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

	podSandbox, err := c.getPodSandboxFromContainerID(containerID)
	if err != nil {
		return nil, err
	}

	return parseContainerDetailsData(c.Name, res.Status, res.Info, podSandbox)
}

func (c *CRIClient) GetPodLabels(sandboxId string) (map[string]string, error) {
	podSandbox, err := getPodSandbox(c, sandboxId)
	if err != nil {
		return nil, err
	}

	return getFilteredPodLabels(podSandbox), nil
}

func (c *CRIClient) getPodSandboxFromContainerID(containerID string) (*runtime.PodSandbox, error) {
	containerID, err := runtimeclient.ParseContainerID(c.Name, containerID)
	if err != nil {
		return nil, err
	}

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

	return getPodSandbox(c, containers[0].PodSandboxId)
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
	extraInfo map[string]string, podSandbox *runtime.PodSandbox,
) (*runtimeclient.ContainerDetailsData, error) {
	containerData := buildContainerData(runtimeName, containerStatus, podSandbox)

	// Create container details structure to be filled.
	containerDetailsData := &runtimeclient.ContainerDetailsData{
		ContainerData: *containerData,
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

// ParseExtraInfoTest exports parseExtraInfo for the tests only (cri_test.go)
// This allows the tests to be in a separate package (package cri_test) so we
// can remove memory expensive dependencies from ig
// (github.com/google/go-cmp/cmp)
func ParseExtraInfoTest(extraInfo map[string]string,
	containerDetailsData *runtimeclient.ContainerDetailsData,
) error {
	return parseExtraInfo(extraInfo, containerDetailsData)
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

func digestFromRef(imageRef string) string {
	splitted := strings.Split(imageRef, "@")
	if len(splitted) == 1 {
		return imageRef
	} else {
		return splitted[1]
	}
}

func getFilteredPodLabels(podSandbox *runtime.PodSandbox) map[string]string {
	labels := map[string]string{}
	for k, v := range podSandbox.GetLabels() {
		if _, ok := podLabelFilter[k]; !ok {
			labels[k] = v
		}
	}
	return labels
}

func buildContainerData(runtimeName types.RuntimeName, container CRIContainer, podSandbox *runtime.PodSandbox) *runtimeclient.ContainerData {
	containerMetadata := container.GetMetadata()
	image := container.GetImage()
	imageRef := container.GetImageRef()

	containerData := &runtimeclient.ContainerData{
		Runtime: runtimeclient.RuntimeContainerData{
			ContainerID:          container.GetId(),
			ContainerName:        strings.TrimPrefix(containerMetadata.GetName(), "/"),
			RuntimeName:          runtimeName,
			ContainerImageName:   image.GetImage(),
			ContainerImageDigest: digestFromRef(imageRef),
			State:                containerStatusStateToRuntimeClientState(container.GetState()),
		},
	}

	// Fill K8S information.
	runtimeclient.EnrichWithK8sMetadata(containerData, container.GetLabels())

	// Initial labels are stored in the pod sandbox
	containerData.K8s.PodLabels = getFilteredPodLabels(podSandbox)

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
