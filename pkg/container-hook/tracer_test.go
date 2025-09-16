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

package containerhook

import (
	"fmt"
	"math/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

func TestContainerHookEvent(t *testing.T) {
	utils.RequireRoot(t)

	type testDefinition struct {
		generateEvent func(t *testing.T) string
		validateEvent func(t *testing.T, info *utils.RunnerInfo, containerID string, events []ContainerEvent)
	}

	for name, test := range map[string]testDefinition{
		"one_container": {
			generateEvent: generateEvent(0),
			validateEvent: utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, containerID string) *ContainerEvent {
				return &ContainerEvent{
					Type:        EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
		"one_container_after_some_failed_containers": {
			generateEvent: generateEvent(2),
			validateEvent: utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, containerID string) *ContainerEvent {
				return &ContainerEvent{
					Type:        EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
		"one_container_after_many_failed_containers": {
			// Test with a number bigger than FANOTIFY_DEFAULT_MAX_GROUPS
			// https://github.com/torvalds/linux/blob/v6.9/fs/notify/fanotify/fanotify_user.c#L32
			// #define FANOTIFY_DEFAULT_MAX_GROUPS	128
			generateEvent: generateEvent(130),
			validateEvent: utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, containerID string) *ContainerEvent {
				return &ContainerEvent{
					Type:        EventTypeAddContainer,
					ContainerID: containerID,
				}
			}),
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()
			events := []ContainerEvent{}
			eventCallback := func(event ContainerEvent) {
				// normalize
				event.ContainerName = ""
				event.ContainerPID = 0
				event.ContainerConfig = ""
				event.Bundle = ""

				events = append(events, event)
			}

			notifier, err := NewContainerNotifier(eventCallback)
			require.NoError(t, err)
			require.NotNil(t, notifier, "Returned notifier was nil")

			containerID := test.generateEvent(t)

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, nil, containerID, events)
		})
	}
}

func TestContainerHookCleanup(t *testing.T) {
	utils.RequireRoot(t)

	containerPendingTimeout = 100 * time.Millisecond
	containerCheckInterval = 1 * time.Second
	t.Cleanup(func() {
		containerPendingTimeout = defaultContainerPendingTimeout
		containerCheckInterval = defaultContainerCheckInterval
	})

	notifier, err := NewContainerNotifier(func(event ContainerEvent) {})
	require.NoError(t, err)
	require.NotNil(t, notifier, "Returned notifier was nil")

	// Give some time for the tracer to capture the events
	time.Sleep(100 * time.Millisecond)

	generateEvent(10)(t)

	time.Sleep(2 * time.Second)

	require.Equal(t, 0, len(notifier.pendingContainers))
	require.Equal(t, 0, len(notifier.futureContainers))

	notifier.Close()
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
