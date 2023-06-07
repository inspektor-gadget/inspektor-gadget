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
	"errors"
	"fmt"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	// Make sure to keep these settings in sync with pkg/resources/manifests/deploy.yaml
	CrioDefaultSocketPath       = "/run/crio/crio.sock"
	PodmanDefaultSocketPath     = "/run/podman/podman.sock"
	ContainerdDefaultSocketPath = "/run/containerd/containerd.sock"
	DockerDefaultSocketPath     = "/run/docker.sock"
)

var ErrPauseContainer = errors.New("it is a pause container")

type K8sContainerData struct {
	types.BasicK8sMetadata

	// Unique identifier of pod running the container.
	PodUID string
}

type RuntimeContainerData struct {
	types.BasicRuntimeMetadata

	// Current state of the container.
	State string
}

// ContainerData contains container information returned from the container
// runtime clients.
type ContainerData struct {
	// Runtime contains all the metadata returned by the container runtime.
	Runtime RuntimeContainerData

	// K8s contains the Kubernetes metadata of the container.
	K8s K8sContainerData
}

// ContainerDetailsData contains container extra information returned from the
// container runtime clients. This information might not be available when
// listing containers.
type ContainerDetailsData struct {
	// ContainerDetailsData contains all ContainerData fields.
	ContainerData

	// Process identifier.
	Pid int

	// Path for the container cgroups.
	CgroupsPath string

	// List of mounts in the container.
	Mounts []ContainerMountData
}

// ContainerMountData contains mount information in ContainerData.
type ContainerMountData struct {
	// Source of the mount in the host file-system.
	Source string

	// Destination of the mount in the container.
	Destination string
}

const (
	// Container was created but has not started running.
	StateCreated = "created"

	// Container is currently running.
	StateRunning = "running"

	// Container has stopped or exited.
	StateExited = "exited"

	// Container has an unknown or unrecognized state.
	StateUnknown = "unknown"
)

const (
	containerLabelK8sContainerName = "io.kubernetes.container.name"
	containerLabelK8sPodName       = "io.kubernetes.pod.name"
	containerLabelK8sPodNamespace  = "io.kubernetes.pod.namespace"
	containerLabelK8sPodUID        = "io.kubernetes.pod.uid"
)

// ContainerRuntimeClient defines the interface to communicate with the
// different container runtimes.
type ContainerRuntimeClient interface {
	// GetContainers returns a slice with the information of all the containers.
	GetContainers() ([]*ContainerData, error)

	// GetContainers returns the information of the container identified by the
	// provided ID.
	GetContainer(containerID string) (*ContainerData, error)

	// GetContainerDetails returns the detailed information of the container
	// identified by the provided ID.
	// The container details cannot be provided prior to container being in
	// running state.
	GetContainerDetails(containerID string) (*ContainerDetailsData, error)

	// Close tears down the connection with the container runtime.
	Close() error
}

func ParseContainerID(expectedRuntime types.RuntimeName, containerID string) (string, error) {
	// If ID contains a prefix, it must match the format "<runtime>://<ID>"
	split := strings.SplitN(containerID, "://", 2)
	if len(split) == 2 {
		if types.String2RuntimeName(split[0]) != expectedRuntime {
			return "", fmt.Errorf("invalid container runtime %q, it should be %q",
				containerID, expectedRuntime)
		}
		return split[1], nil
	}

	return split[0], nil
}

func EnrichWithK8sMetadata(container *ContainerData, labels map[string]string) {
	if containerName, ok := labels[containerLabelK8sContainerName]; ok {
		container.K8s.Container = containerName
	}
	if podName, ok := labels[containerLabelK8sPodName]; ok {
		container.K8s.Pod = podName
	}
	if podNamespace, ok := labels[containerLabelK8sPodNamespace]; ok {
		container.K8s.Namespace = podNamespace
	}
	if podUID, ok := labels[containerLabelK8sPodUID]; ok {
		container.K8s.PodUID = podUID
	}
}

// IsEnrichedWithK8sMetadata returns true if the container already contains
// the Kubernetes metadata a container runtime client is able to provide.
func IsEnrichedWithK8sMetadata(k8s types.BasicK8sMetadata) bool {
	return k8s.IsEnriched()
}

// IsEnrichedWithRuntimeMetadata returns true if the container already contains
// the runtime metadata a container runtime client is able to provide.
func IsEnrichedWithRuntimeMetadata(runtime types.BasicRuntimeMetadata) bool {
	return runtime.IsEnriched()
}
