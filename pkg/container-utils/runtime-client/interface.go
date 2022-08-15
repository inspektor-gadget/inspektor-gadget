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
