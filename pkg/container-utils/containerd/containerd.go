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

package containerd

import (
	"context"
	"fmt"
	"time"

	"github.com/containerd/containerd"
	"github.com/containerd/containerd/errdefs"
	log "github.com/sirupsen/logrus"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
)

const (
	DefaultTimeout = 2 * time.Second

	LabelK8sContainerName         = "io.kubernetes.container.name"
	LabelK8sContainerdKind        = "io.cri-containerd.kind"
	LabelK8sContainerdKindSandbox = "sandbox"

	logPrefix = "ContainerdClient: "
)

type ContainerdClient struct {
	client *containerd.Client
}

func NewContainerdClient(socketPath string) (runtimeclient.ContainerRuntimeClient, error) {
	if socketPath == "" {
		socketPath = runtimeclient.ContainerdDefaultSocketPath
	}

	client, err := containerd.New(socketPath,
		containerd.WithTimeout(DefaultTimeout),
		containerd.WithDefaultNamespace("k8s.io"),
	)
	if err != nil {
		return nil, err
	}

	return &ContainerdClient{
		client: client,
	}, nil
}

func (c *ContainerdClient) Close() error {
	if c.client != nil {
		return c.client.Close()
	}
	return nil
}

func (c *ContainerdClient) GetContainers() ([]*runtimeclient.ContainerData, error) {
	containers, err := c.client.Containers(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing containers: %w", err)
	}

	ret := make([]*runtimeclient.ContainerData, 0, len(containers))
	for _, container := range containers {
		if isSandboxContainer(container) {
			log.Debugf("%scontainer %q is a sandbox container. Temporary skipping it", logPrefix, container.ID())
			continue
		}

		task, err := getContainerTask(container)
		if err != nil {
			log.Debugf("%sgetting containerTask for container %q: %s", logPrefix, container.ID(), err)
			continue
		}

		containerData, err := taskAndContainerToContainerData(task, container)
		if err != nil {
			log.Debugf("%screating containerData for container %q: %s", logPrefix, container.ID(), err)
			continue
		}

		ret = append(ret, containerData)
	}

	return ret, nil
}

func (c *ContainerdClient) GetContainer(containerID string) (*runtimeclient.ContainerData, error) {
	container, err := c.getContainer(containerID)
	if err != nil {
		return nil, err
	}

	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing labels of container %q: %w", container.ID(), err)
	}

	// State is getting set to `Created` here for the following reasons:
	// 1. GetContainer is only getting called on new created containers
	// 2. We would need to get the Task for the Container. containerd needs to aquire a mutex
	//    that is currently hold by the creating process, which we interrupted -> deadlock
	containerData := &runtimeclient.ContainerData{
		ID:      container.ID(),
		Name:    getContainerName(container),
		State:   runtimeclient.StateCreated,
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}

func (c *ContainerdClient) GetContainerDetails(containerID string) (*runtimeclient.ContainerDetailsData, error) {
	containerID, err := runtimeclient.ParseContainerID(runtimeclient.ContainerdName, containerID)
	if err != nil {
		return nil, err
	}

	containerData, container, task, err := c.getContainerDataAndContainerAndTask(containerID)
	if err != nil {
		return nil, err
	}
	if task.pid == 0 {
		return nil, fmt.Errorf("got zero pid")
	}

	spec, err := container.Spec(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting spec for container %q: %w", containerID, err)
	}

	mountData := make([]runtimeclient.ContainerMountData, len(spec.Mounts))
	for i := range spec.Mounts {
		mount := spec.Mounts[i]
		mountData[i] = runtimeclient.ContainerMountData{
			Source:      mount.Source,
			Destination: mount.Destination,
		}
	}

	return &runtimeclient.ContainerDetailsData{
		ContainerData: *containerData,
		Pid:           int(task.pid),
		CgroupsPath:   spec.Linux.CgroupsPath,
		Mounts:        mountData,
	}, nil
}

func (c *ContainerdClient) getContainerDataAndContainerAndTask(containerID string) (*runtimeclient.ContainerData, containerd.Container, *containerTask, error) {
	container, err := c.getContainer(containerID)
	if err != nil {
		return nil, nil, nil, err
	}

	task, err := getContainerTask(container)
	if err != nil {
		return nil, nil, nil, err
	}

	containerData, err := taskAndContainerToContainerData(task, container)
	if err != nil {
		return nil, nil, nil, err
	}

	return containerData, container, task, nil
}

// getContainer returns the corresponding container.Container instance to
// the given id
func (c *ContainerdClient) getContainer(id string) (containerd.Container, error) {
	container, err := c.client.LoadContainer(context.TODO(), id)
	if err != nil {
		return nil, fmt.Errorf("loading container with id %q: %w", id, err)
	}

	if isSandboxContainer(container) {
		log.Debugf("%scontainer %q is a sandbox container. Temporary skipping it", logPrefix, container.ID())
		return nil, runtimeclient.ErrPauseContainer
	}

	return container, nil
}

// containerTask represents the task information for a given container.
type containerTask struct {
	status string
	pid    uint32
}

// getContainerTask returns the containerTask information for a given container.
// If the container is not running yet, it returns a containerTask with status
// StateCreated and pid 0.
func getContainerTask(container containerd.Container) (*containerTask, error) {
	task, err := container.Task(context.TODO(), nil)
	if err != nil {
		// According to nerdctl, if there is no task, we can assume the
		// container was just created but it is not running yet:
		// https://github.com/containerd/nerdctl/blob/b0a75d880ef9e6d1f1a8752804c9087ee2d02f73/pkg/formatter/formatter.go#L48-L55
		if !errdefs.IsNotFound(err) {
			return nil, fmt.Errorf("getting task for container %q: %w", container.ID(), err)
		}

		t := &containerTask{
			status: runtimeclient.StateCreated,
			pid:    0,
		}
		log.Debugf("%sNo task for %q. Assuming it is in %q status",
			logPrefix, container.ID(), t.status)

		return t, nil
	}

	containerdStatus, err := task.Status(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("getting status of task for container %q: %w", container.ID(), err)
	}

	return &containerTask{
		status: processStatusStateToRuntimeClientState(containerdStatus.Status),
		pid:    task.Pid(),
	}, nil
}

// Constructs a ContainerData from a containerTask and containerd.Container
// The extra containerd.Container parameter saves an additional call to the API
func taskAndContainerToContainerData(task *containerTask, container containerd.Container) (*runtimeclient.ContainerData, error) {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return nil, fmt.Errorf("listing labels of container %q: %w", container.ID(), err)
	}

	containerData := &runtimeclient.ContainerData{
		ID:      container.ID(),
		Name:    getContainerName(container),
		State:   task.status,
		Runtime: runtimeclient.ContainerdName,
	}
	runtimeclient.EnrichWithK8sMetadata(containerData, labels)
	return containerData, nil
}

// Checks if the K8s Label for the Containerkind equals to sandbox
func isSandboxContainer(container containerd.Container) bool {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return false
	}

	if kind, ok := labels[LabelK8sContainerdKind]; ok {
		return kind == LabelK8sContainerdKindSandbox
	}

	return false
}

// Convert the state from container status to state of runtime client.
func processStatusStateToRuntimeClientState(status containerd.ProcessStatus) string {
	switch status {
	case containerd.Created:
		return runtimeclient.StateCreated
	case containerd.Running:
		return runtimeclient.StateRunning
	case containerd.Stopped:
		return runtimeclient.StateExited
	default:
		return runtimeclient.StateUnknown
	}
}

// getContainerName returns the name of the container. If the container is
// managed by Kubernetes, it returns the name of the container as defined in
// Kubernetes. Otherwise, it returns the container ID.
func getContainerName(container containerd.Container) string {
	labels, err := container.Labels(context.TODO())
	if err != nil {
		return container.ID()
	}

	if k8sName, ok := labels[LabelK8sContainerName]; ok {
		return k8sName
	}

	return container.ID()
}
