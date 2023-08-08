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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

type DockerManager struct{}

func (dm *DockerManager) NewContainer(name, cmd string, opts ...containerOption) IntegrationTestsContainer {
	c := &DockerContainer{}

	for _, o := range opts {
		o(&c.cOptions)
	}
	c.options = append(c.options, testutils.WithContext(context.Background()))

	c.Container = testutils.NewDockerContainer(name, cmd, c.options...)
	return c
}

// DockerContainer implements TestStep for docker containers
type DockerContainer struct {
	testutils.Container
	cOptions
}

func (d *DockerContainer) IsCleanup() bool {
	return d.cleanup
}

func (d *DockerContainer) IsStartAndStop() bool {
	return d.startAndStop
}
