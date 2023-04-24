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

func (*ContainerdManager) NewContainer(spec ContainerSpec) ContainerInterface {
	return &ContainerdContainer{
		ContainerSpec: spec,
	}
}

// ContainerdContainer implements TestStep for containerd containers
type ContainerdContainer struct {
	ContainerSpec
	started bool
}

func (d *ContainerdContainer) Run(t *testing.T) {
	opts := append(optionsFromContainerOptions(d.Options), testutils.WithName(d.Name))
	testutils.RunContainerdContainer(context.Background(), t, d.Cmd, opts...)
}

func (d *ContainerdContainer) Start(t *testing.T) {
	if d.started {
		t.Logf("Warn(%s): trying to start already running container\n", d.Name)
		return
	}
	opts := append(optionsFromContainerOptions(d.Options), testutils.WithName(d.Name), testutils.WithoutRemoval(), testutils.WithoutWait())
	testutils.RunContainerdContainer(context.Background(), t, d.Cmd, opts...)
	d.started = true
}

func (d *ContainerdContainer) Stop(t *testing.T) {
	testutils.RemoveContainerdContainer(context.Background(), t, d.Name)
	d.started = false
}

func (d *ContainerdContainer) IsCleanup() bool {
	return d.Cleanup
}

func (d *ContainerdContainer) IsStartAndStop() bool {
	return d.StartAndStop
}

func (d *ContainerdContainer) Running() bool {
	return d.started
}
