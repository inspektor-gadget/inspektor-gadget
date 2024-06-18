// Copyright 2024 The Inspektor Gadget authors
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

//go:build linux
// +build linux

package containerhook_test

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
)

func TestContainerHook(t *testing.T) {
	utilstest.RequireRoot(t)

	type testDefinition struct {
		generateEvent func(t *testing.T) string
		validateEvent func(t *testing.T, info *utilstest.RunnerInfo, containerID string, events []containerhook.ContainerEvent)
	}

	for name, test := range map[string]testDefinition{
		"one_container": {
			generateEvent: generateEvent(0),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, containerID string) *containerhook.ContainerEvent {
				return &containerhook.ContainerEvent{
					Type:        containerhook.EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
		"one_container_after_some_failed_containers": {
			generateEvent: generateEvent(2),
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, containerID string) *containerhook.ContainerEvent {
				return &containerhook.ContainerEvent{
					Type:        containerhook.EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
		"one_container_after_many_failed_containers": {
			// Test with a number bigger than FANOTIFY_DEFAULT_MAX_GROUPS
			// https://github.com/torvalds/linux/blob/v6.9/fs/notify/fanotify/fanotify_user.c#L32
			// #define FANOTIFY_DEFAULT_MAX_GROUPS	128
			generateEvent: generateEvent(3), // TODO: change this number to 130
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, containerID string) *containerhook.ContainerEvent {
				return &containerhook.ContainerEvent{
					Type:        containerhook.EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			events := []containerhook.ContainerEvent{}
			eventCallback := func(event containerhook.ContainerEvent) {
				// normalize
				event.ContainerName = ""
				event.ContainerPID = 0
				event.ContainerConfig = nil
				event.Bundle = ""

				events = append(events, event)
			}

			notifier, err := containerhook.NewContainerNotifier(eventCallback)
			require.NoError(t, err)
			require.NotNil(t, notifier, "Returned notifier was nil")

			containerID := test.generateEvent(t)

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, nil, containerID, events)
		})
	}
}

func generateEvent(nfailure int) func(t *testing.T) string {
	return func(t *testing.T) string {
		// Failed container with bad configuration
		for i := 0; i < nfailure; i++ {
			fmt.Printf("running %d\n", i)
			name := fmt.Sprintf("ig-test-%d-%d", i, rand.Uint32())
			// /dev/null/invalid is not a valid path, hence it fails during 'runc create'
			mounts := []string{"/dev/null:/dev/null/invalid"}
			container := testutils.NewDockerContainer(name, "id",
				testutils.WithoutLogs(),
				testutils.WithBindMounts(mounts),
				testutils.WithExpectStartError())
			container.Run(t)
		}

		// Good container with valid configuration
		name := fmt.Sprintf("ig-test-%d", rand.Uint32())
		container := testutils.NewDockerContainer(name, "id", testutils.WithoutLogs())
		container.Run(t)
		return container.ID()
	}
}
