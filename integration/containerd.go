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

package integration

import (
	"context"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

type ContainerdManager struct{}

func (cm *ContainerdManager) NewContainer(name, cmd string, opts ...containerOption) ContainerInterface {
	c := &ContainerdContainer{
		containerSpec: containerSpec{
			name: name,
			cmd:  cmd,
		},
	}
	for _, o := range opts {
		o(&c.containerSpec)
	}
	return c
}

// ContainerdContainer implements TestStep for containerd containers
type ContainerdContainer struct {
	containerSpec
	started bool
}

func (c *ContainerdContainer) Run(t *testing.T) {
	opts := append(c.options, testutils.WithName(c.name))
	testutils.RunContainerdContainer(context.Background(), t, c.cmd, opts...)
}

func (c *ContainerdContainer) Start(t *testing.T) {
	if c.started {
		t.Logf("Warn(%s): trying to start already running container\n", c.name)
		return
	}
	opts := append(c.options, testutils.WithName(c.name), testutils.WithoutRemoval(), testutils.WithoutWait())
	testutils.RunContainerdContainer(context.Background(), t, c.cmd, opts...)
	c.started = true
}

func (c *ContainerdContainer) Stop(t *testing.T) {
	testutils.RemoveContainerdContainer(context.Background(), t, c.name)
	c.started = false
}

func (c *ContainerdContainer) IsCleanup() bool {
	return c.cleanup
}

func (c *ContainerdContainer) IsStartAndStop() bool {
	return c.startAndStop
}

func (c *ContainerdContainer) Running() bool {
	return c.started
}
