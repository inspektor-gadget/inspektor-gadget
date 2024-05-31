// Copyright 2023-2024 The Inspektor Gadget authors
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

package containers

import (
	"fmt"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type ContainerFactory interface {
	NewContainer(name, cmd string, opts ...ContainerOption) *TestContainer
}

// NewContainerFactory returns a new instance of a ContainerFactory based on the
// container runtime. The returned factory can be used to create new container
// instances which can be used in tests.
func NewContainerFactory(containerRuntime string) (ContainerFactory, error) {
	switch types.String2RuntimeName(containerRuntime) {
	case types.RuntimeNameDocker:
		return &DockerManager{}, nil
	case types.RuntimeNameContainerd:
		return &ContainerdManager{}, nil
	default:
		if containerRuntime == RuntimeKubernetes {
			return &K8sManager{}, nil
		}

		return nil, fmt.Errorf("unknown container runtime %q", containerRuntime)
	}
}

// TestContainer is a wrapper around testutils.Container that implements the
// missing functions from the TestStep interface. This allows to use the
// container as a step in a test.
type TestContainer struct {
	testutils.Container
	cOptions
}
