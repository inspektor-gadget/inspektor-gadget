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

// DockerContainer implements TestStep for docker containers
type DockerContainer struct {
	Name         string
	Cmd          string
	Options      []dockerOption
	Cleanup      bool
	StartAndStop bool

	started bool
}

func (d *DockerContainer) Run(t *testing.T) {
	opts := append(optionsFromDockerOptions(d.Options), testutils.WithName(d.Name))
	testutils.RunDockerContainer(context.Background(), t, d.Cmd, opts...)
}

func (d *DockerContainer) Start(t *testing.T) {
	if d.started {
		t.Logf("Warn(%s): trying to start already running container\n", d.Name)
		return
	}
	opts := append(optionsFromDockerOptions(d.Options), testutils.WithName(d.Name), testutils.WithoutRemoval(), testutils.WithoutWait())
	testutils.RunDockerContainer(context.Background(), t, d.Cmd, opts...)
	d.started = true
}

func (d *DockerContainer) Stop(t *testing.T) {
	testutils.RemoveDockerContainer(context.Background(), t, d.Name)
	d.started = false
}

func (d *DockerContainer) IsCleanup() bool {
	return d.Cleanup
}

func (d *DockerContainer) IsStartAndStop() bool {
	return d.StartAndStop
}

func (d *DockerContainer) Running() bool {
	return d.started
}

// dockerOption wraps testutils.Option to allow certain values only
type dockerOption struct {
	opt testutils.Option
}

func NewDockerOptions(opts ...dockerOption) []dockerOption {
	return opts
}

func optionsFromDockerOptions(dockerOptions []dockerOption) []testutils.Option {
	var opts []testutils.Option
	for _, do := range dockerOptions {
		opts = append(opts, do.opt)
	}
	return opts
}

func WithDockerImage(image string) dockerOption {
	return dockerOption{opt: testutils.WithImage(image)}
}

func WithDockerSeccompProfile(profile string) dockerOption {
	return dockerOption{opt: testutils.WithSeccompProfile(profile)}
}

func WithDockerPrivileged() dockerOption {
	return dockerOption{opt: testutils.WithPrivileged()}
}
