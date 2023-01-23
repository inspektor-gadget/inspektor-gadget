//go:build linux
// +build linux

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

package tracer_test

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestOpenTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	if tracer == nil {
		t.Fatal("Returned tracer was nil")
	}
}

func TestOpenTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

func createTracer(
	t *testing.T, config *tracer.Config, callback func(*types.Event),
) *tracer.Tracer {
	t.Helper()

	tracer, err := tracer.NewTracer(config, nil, callback)
	if err != nil {
		t.Fatalf("Error creating tracer: %s", err)
	}
	t.Cleanup(tracer.Stop)

	return tracer
}

func TestOpenTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const unprivilegedUID = int(1435)

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *tracer.Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() (int, error)
		validateEvent   func(*testing.T, *utilstest.RunnerInfo, int, []types.Event)
	}

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					MountNsID: info.MountNsID,
					Pid:       uint32(info.Pid),
					UID:       uint32(info.UID),
					Comm:      info.Comm,
					Fd:        fd,
					Ret:       fd,
					Err:       0,
					Path:      "/dev/null",
				}
			}),
		},
		"captures_no_events_with_no_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, 0),
				}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectNoEvent[types.Event, int],
		},
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					MountNsID: info.MountNsID,
					Pid:       uint32(info.Pid),
					UID:       uint32(info.UID),
					Comm:      info.Comm,
					Fd:        fd,
					Ret:       fd,
					Err:       0,
					Path:      "/dev/null",
				}
			}),
		},
		"event_has_UID_of_user_generating_event": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig:  &utilstest.RunnerConfig{UID: unprivilegedUID},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ int, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("One event expected")
				}

				utilstest.Equal(t, uint32(info.UID), events[0].UID,
					"Captured event has bad UID")
			},
		},
		"event_has_correct_error": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func() (int, error) {
				_, err := unix.Open("non-existing-file", 0, 0)
				if err == nil {
					return 0, fmt.Errorf("error was expected")
				}

				return -1, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ int, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("One event expected")
				}

				utilstest.Equal(t, int(unix.ENOENT), events[0].Err,
					"Captured event has bad Err")
			},
		},
		"event_has_correct_ret_on_error": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func() (int, error) {
				_, err := unix.Open("non-existing-file", 0, 0)
				if err == nil {
					return 0, fmt.Errorf("error was expected")
				}

				return -1, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ int, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("One event expected")
				}

				utilstest.Equal(t, -int(unix.ENOENT), events[0].Ret,
					"Captured event has bad Ret")
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			events := []types.Event{}
			eventCallback := func(event *types.Event) {
				// normalize
				event.Timestamp = 0

				events = append(events, *event)
			}

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			createTracer(t, test.getTracerConfig(runner.Info), eventCallback)

			var fd int

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				fd, err = test.generateEvent()
				return err
			})

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, runner.Info, fd, events)
		})

	}
}

func TestOpenTracerMultipleMntNsIDsFilter(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	events := []types.Event{}
	eventCallback := func(event *types.Event) {
		events = append(events, *event)
	}

	// struct with only fields we want to check on this test
	type expectedEvent struct {
		mntNsID uint64
		fd      int
	}

	const n int = 5
	runners := make([]*utilstest.Runner, n)
	expectedEvents := make([]expectedEvent, n)
	mntNsIDs := make([]uint64, n)

	for i := 0; i < n; i++ {
		runners[i] = utilstest.NewRunnerWithTest(t, nil)
		mntNsIDs[i] = runners[i].Info.MountNsID
		expectedEvents[i].mntNsID = runners[i].Info.MountNsID
	}

	// Filter events from all runners but last one
	config := &tracer.Config{
		MountnsMap: utilstest.CreateMntNsFilterMap(t, mntNsIDs[:n-1]...),
	}

	createTracer(t, config, eventCallback)

	for i := 0; i < n; i++ {
		utilstest.RunWithRunner(t, runners[i], func() error {
			var err error
			expectedEvents[i].fd, err = generateEvent()
			return err
		})
	}

	// Give some time for the tracer to capture the events
	time.Sleep(100 * time.Millisecond)

	if len(events) != n-1 {
		t.Fatalf("%d events were expected, %d found", n-1, len(events))
	}

	// Pop last event since it shouldn't have been captured
	expectedEvents = expectedEvents[:n-1]

	// Order or events is not guaranteed, then we need to sort before comparing
	sort.Slice(expectedEvents, func(i, j int) bool {
		return expectedEvents[i].mntNsID < expectedEvents[j].mntNsID
	})
	sort.Slice(events, func(i, j int) bool {
		return events[i].MountNsID < events[j].MountNsID
	})

	for i := 0; i < n-1; i++ {
		utilstest.Equal(t, expectedEvents[i].mntNsID, events[i].MountNsID,
			"Captured event has bad MountNsID")

		utilstest.Equal(t, expectedEvents[i].fd, events[i].Fd,
			"Captured event has bad fd")
	}
}

// Function to generate an event used most of the times.
// Returns fd of opened file.
func generateEvent() (int, error) {
	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}

	unix.Close(fd)

	return fd, nil
}
