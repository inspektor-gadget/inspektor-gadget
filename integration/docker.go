// Copyright 2022-2023 The Inspektor Gadget authors
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

type DockerManager struct{}

func (dm *DockerManager) NewContainer(name, cmd string, opts ...containerOption) ContainerInterface {
	c := &DockerContainer{
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

// DockerContainer implements TestStep for docker containers
type DockerContainer struct {
	containerSpec

	started bool
}

func (d *DockerContainer) Run(t *testing.T) {
	opts := append(d.options, testutils.WithName(d.name))
	testutils.RunDockerContainer(context.Background(), t, d.cmd, opts...)
}

func (d *DockerContainer) Start(t *testing.T) {
	if d.started {
		t.Logf("Warn(%s): trying to start already running container\n", d.name)
		return
	}
	opts := append(d.options, testutils.WithName(d.name), testutils.WithoutRemoval(), testutils.WithoutWait())
	testutils.RunDockerContainer(context.Background(), t, d.cmd, opts...)
	d.started = true
}

func (d *DockerContainer) Stop(t *testing.T) {
	testutils.StopDockerContainer(context.Background(), t, d.name)
	d.started = false
}

func (d *DockerContainer) IsCleanup() bool {
	return d.cleanup
}

func (d *DockerContainer) IsStartAndStop() bool {
	return d.startAndStop
}

func (d *DockerContainer) Running() bool {
	return d.started
}
