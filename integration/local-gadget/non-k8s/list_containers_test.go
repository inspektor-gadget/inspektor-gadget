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

package main

import (
	"fmt"
	"testing"

	. "github.com/inspektor-gadget/inspektor-gadget/integration"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
)

func TestFilterByContainerName(t *testing.T) {
	t.Parallel()

	cn := "test-filtered-container"
	listContainersCmd := &Command{
		Name: "RunFilterByContainerName",
		Cmd:  fmt.Sprintf("./local-gadget list-containers -o json --runtimes=docker --containername=%s", cn),
		ExpectedOutputFn: func(output string) error {
			expectedContainer := &containercollection.Container{
				Name:    cn,
				Runtime: "docker",
			}

			normalize := func(c *containercollection.Container) {
				c.ID = ""
				c.Pid = 0
				c.OciConfig = nil
				c.Bundle = ""
				c.Mntns = 0
				c.Netns = 0
				c.CgroupPath = ""
				c.CgroupID = 0
				c.CgroupV1 = ""
				c.CgroupV2 = ""
				c.Labels = nil
				c.PodUID = ""
			}

			return ExpectAllInArrayToMatch(output, normalize, expectedContainer)
		},
	}

	testSteps := []TestStep{
		&DockerContainer{
			Name:         cn,
			Cmd:          "sleep inf",
			StartAndStop: true,
		},
		SleepForSecondsCommand(2),
		listContainersCmd,
	}

	RunTestSteps(testSteps, t)
}

func TestWatchContainers(t *testing.T) {
	t.Parallel()

	cn := "test-watched-container"
	watchContainersCommand := &Command{
		Name:         "RunWatchContainers",
		Cmd:          fmt.Sprintf("./local-gadget list-containers -o json --watch --runtimes=docker -c %s", cn),
		StartAndStop: true,
		ExpectedOutputFn: func(output string) error {
			expectedEvents := []*containercollection.PubSubEvent{
				{
					Type: containercollection.EventTypeAddContainer,
					Container: &containercollection.Container{
						Name:    cn,
						Runtime: "docker",
					},
				},
				{
					Type: containercollection.EventTypeRemoveContainer,
					Container: &containercollection.Container{
						Name:    cn,
						Runtime: "docker",
					},
				},
			}

			normalize := func(e *containercollection.PubSubEvent) {
				e.Container.ID = ""
				e.Container.Pid = 0
				e.Container.OciConfig = nil
				e.Container.Bundle = ""
				e.Container.Mntns = 0
				e.Container.Netns = 0
				e.Container.CgroupPath = ""
				e.Container.CgroupID = 0
				e.Container.CgroupV1 = ""
				e.Container.CgroupV2 = ""
				e.Container.Labels = nil
				e.Container.PodUID = ""
				e.Timestamp = ""
			}

			return ExpectEntriesToMatch(output, normalize, expectedEvents...)
		},
	}

	testSteps := []TestStep{
		watchContainersCommand,
		SleepForSecondsCommand(2),
		&DockerContainer{
			Name: cn,
			Cmd:  "echo I am short lived container",
		},
	}

	RunTestSteps(testSteps, t)
}
