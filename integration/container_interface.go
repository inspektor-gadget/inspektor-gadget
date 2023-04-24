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

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

type ContainerSpec struct {
	Name         string
	Cmd          string
	Options      []containerOption
	Cleanup      bool
	StartAndStop bool
}

type ContainerFactory interface {
	NewContainer(ContainerSpec) ContainerInterface
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
	switch containerRuntime {
	case runtimeclient.DockerName:
		return &DockerManager{}, nil
	case runtimeclient.ContainerdName:
		return &ContainerdManager{}, nil
	default:
		return nil, fmt.Errorf("unknown container runtime %q", containerRuntime)
	}
}

// containerdOption wraps testutils.Option to allow certain values only
type containerOption struct {
	opt          testutils.Option
	Name         string
	Cmd          string
	Cleanup      bool
	StartAndStop bool
}

func NewContainerOptions(opts ...containerOption) []containerOption {
	return opts
}

func optionsFromContainerOptions(containerOption []containerOption) []testutils.Option {
	var opts []testutils.Option
	for _, do := range containerOption {
		opts = append(opts, do.opt)
	}
	return opts
}

func WithName(name string) containerOption {
	return containerOption{opt: testutils.WithName(name)}
}

func WithContainerImage(image string) containerOption {
	return containerOption{opt: testutils.WithImage(image)}
}

func WithContainerSeccompProfile(profile string) containerOption {
	return containerOption{opt: testutils.WithSeccompProfile(profile)}
}
