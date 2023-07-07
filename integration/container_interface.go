// Copyright 2023 The Inspektor Gadget authors
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

package integration

import (
	"fmt"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type ContainerFactory interface {
	NewContainer(name, cmd string, opts ...containerOption) ContainerInterface
}

type ContainerInterface interface {
	Run(t *testing.T)
	Start(t *testing.T)
	Stop(t *testing.T)
	IsCleanup() bool
	IsStartAndStop() bool
	Running() bool
}

func NewContainerFactory(containerRuntime string) (ContainerFactory, error) {
	switch types.String2RuntimeName(containerRuntime) {
	case types.RuntimeNameDocker:
		return &DockerManager{}, nil
	case types.RuntimeNameContainerd:
		return &ContainerdManager{}, nil
	default:
		return nil, fmt.Errorf("unknown container runtime %q", containerRuntime)
	}
}

type containerSpec struct {
	// Options
	options      []testutils.Option
	cleanup      bool
	startAndStop bool

	// Internal
	started bool
}

// containerOption is a function that modifies a ContainerSpec and exposes only
// few options from testutils.Option to the user.
type containerOption func(specs *containerSpec)

func WithContainerImage(image string) containerOption {
	return func(specs *containerSpec) {
		specs.options = append(specs.options, testutils.WithImage(image))
	}
}

func WithContainerSeccompProfile(profile string) containerOption {
	return func(specs *containerSpec) {
		specs.options = append(specs.options, testutils.WithSeccompProfile(profile))
	}
}

func WithCleanup() containerOption {
	return func(specs *containerSpec) {
		specs.cleanup = true
	}
}

func WithStartAndStop() containerOption {
	return func(specs *containerSpec) {
		specs.startAndStop = true
	}
}
