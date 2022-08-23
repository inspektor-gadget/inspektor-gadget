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
	"fmt"
	"strings"
)

// ContainerData contains container information returned from the container
// runtime clients.
type ContainerData struct {
	// ID is the container ID without the container runtime prefix. For
	// instance, "cri-o://" for CRI-O.
	ID string

	// Name is the container name. In the case the container runtime response
	// with multiples, Name contains only the first element.
	Name string

	// Current state of the container.
	State string

	// Runtime is the name of the runtime (e.g. docker, cri-o, containerd). It
	// is useful to distinguish who is the "owner" of each container in a list
	// of containers collected from multiples runtimes.
	Runtime string

	// extraInfo contains the extra information that might not be available
	// when listing the containers.
	ExtraInfo *ContainerExtraInfo
}

// ContainerExtraInfo contains container extra information returned from the
// container runtime clients. This information might not be available when
// listing containers.
type ContainerExtraInfo struct {
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

// ContainerRuntimeClient defines the interface to communicate with the
// different container runtimes.
type ContainerRuntimeClient interface {
	// GetContainers returns a slice with the information of all the containers.
	// Notice ContainerData.ContainerExtraInfo will not be available because
	// retrieving such information requires an extra call to the runtime, and
	// users may not want to do that for every container. Use GetContainer to
	// get that information only for the containers of interest.
	GetContainers() ([]*ContainerData, error)

	// GetContainer returns a detailed information of the container identified
	// by the provided ID. Unlike GetContainers, the
	// ContainerData.ContainerExtraInfo will always be available in this case.
	GetContainer(containerID string) (*ContainerData, error)

	// Close tears down the connection with the container runtime.
	Close() error
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
