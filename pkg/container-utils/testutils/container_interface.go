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

package testutils

import (
	"fmt"
	"testing"

	"github.com/docker/go-connections/nat"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type containerSpec struct {
	name    string
	cmd     string
	options *containerOptions

	// Internal state
	id           string
	ip           string
	pid          int
	started      bool
	portBindings nat.PortMap
}

type Container interface {
	DisplayName() string
	Run(t *testing.T)
	Start(t *testing.T)
	Stop(t *testing.T)
	ID() string
	IP() string
	Pid() int
	Running() bool
	PortBindings() nat.PortMap
}

func (c *containerSpec) ID() string {
	return c.id
}

func (c *containerSpec) IP() string {
	return c.ip
}

func (c *containerSpec) Pid() int {
	return c.pid
}

func (c *containerSpec) Running() bool {
	return c.started
}

func (c *containerSpec) PortBindings() nat.PortMap {
	return c.portBindings
}

func (c *containerSpec) DisplayName() string {
	return c.name + ": " + c.cmd
}

var SupportedContainerRuntimes = []types.RuntimeName{
	types.RuntimeNameDocker,
	types.RuntimeNameContainerd,
}

func NewContainer(runtime types.RuntimeName, name, cmd string, options ...Option) (Container, error) {
	switch runtime {
	case types.RuntimeNameDocker:
		return NewDockerContainer(name, cmd, options...), nil
	case types.RuntimeNameContainerd:
		return NewContainerdContainer(name, cmd, options...), nil
	default:
		return nil, fmt.Errorf("unknown container runtime %q", runtime)
	}
}
