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

package tracer

import (
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"testing"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	snapshotProcessTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type collectorFunc func(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*snapshotProcessTypes.Event, error)

func BenchmarkSnapshotProcessEBPFTracer(b *testing.B) {
	benchmarkTracer(b, runeBPFCollector)
}

func BenchmarkSnapshotProcessProcfsTracer(b *testing.B) {
	benchmarkTracer(b, runProcfsCollector)
}

func benchmarkTracer(b *testing.B, runCollector collectorFunc) {
	utilstest.RequireRoot(b)

	for n := 0; n < b.N; n++ {
		_, err := runCollector(&Config{}, nil)
		if err != nil {
			b.Fatalf("benchmarking collector: %s", err)
		}
	}
}

func TestSnapshotProcessEBPFTracer(t *testing.T) {
	testTracer(t, runeBPFCollector)
}

func TestSnapshotProcessProcfsTracer(t *testing.T) {
	testTracer(t, runProcfsCollector)
}

func testTracer(t *testing.T, runCollector collectorFunc) {
	t.Parallel()

	utilstest.RequireRoot(t)

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() (int, error)
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []snapshotProcessTypes.Event)
	}

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *snapshotProcessTypes.Event {
				return &snapshotProcessTypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Command:   "sleep",
					Pid:       sleepPid,
					Tid:       sleepPid,
					ParentPid: 0,
					MountNsID: info.MountNsID,
				}
			}),
		},
		"captures_no_events_with_no_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				// We can't use 0 as the mntnsid because the tracer will collect
				// some defunct processes that don't have any mntnsid defined
				// anymore. Then, we set the network namespace inode id to be sure
				// there is not any mount namespace using that same inode.
				mntns, _ := containerutils.GetNetNs(os.Getpid())
				return &Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, mntns),
				}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectNoEvent[snapshotProcessTypes.Event, int],
		},
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: generateEvent,
			// We have to use ExpectAtLeastOneEvent because it's possible that the
			// golang thread that executes this test is also captured
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *snapshotProcessTypes.Event {
				return &snapshotProcessTypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Command:   "sleep",
					Pid:       sleepPid,
					Tid:       sleepPid,
					MountNsID: info.MountNsID,
				}
			}),
		},
		// This is a hacky way to test this: one of the threads of the goroutine is moved to
		// the mount namespace created for testing, also the sleep process we execute is
		// there. That's why 2 events are expected. A better way would be to execute a
		// command that creates multiple threads and check if we capture all of them, but so
		// far I haven't found an easy way to do so. One idea is to use python but it seems
		// too complicated and will introduce another dependency for testing.
		"captures_events_with_matching_filter_threads": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{
					MountnsMap:  utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					ShowThreads: true,
				}
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []snapshotProcessTypes.Event) {
				if len(events) != 2 {
					t.Fatalf("%d events expected, found: %d", 2, len(events))
				}

				expectedEvent := &snapshotProcessTypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Command:   "sleep",
					Pid:       sleepPid,
					Tid:       sleepPid,
					ParentPid: 0,
					MountNsID: info.MountNsID,
				}

				for _, event := range events {
					if reflect.DeepEqual(expectedEvent, &event) {
						return
					}
				}

				t.Fatalf("Event wasn't captured")
			},
		},
		"no_threads_are_captured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *Config {
				return &Config{}
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []snapshotProcessTypes.Event) {
				if len(events) == 0 {
					t.Fatalf("no events were captured")
				}
				for _, event := range events {
					if event.Pid != event.Tid {
						t.Fatalf("thread %d was captured", event.Tid)
					}
				}
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			var sleepPid int

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				sleepPid, err = test.generateEvent()
				return err
			})

			events, err := runCollector(test.getTracerConfig(runner.Info), nil)
			if err != nil {
				t.Fatalf("running collector: %s", err)
			}

			// TODO: This won't be required once we pass pointers everywhere
			validateEvents := []snapshotProcessTypes.Event{}
			for _, event := range events {
				// Normalize parent PID to avoid failing tests as this is not trivial to
				// guess the parent PID.
				event.ParentPid = 0

				validateEvents = append(validateEvents, *event)
			}

			test.validateEvent(t, runner.Info, sleepPid, validateEvents)
		})
	}
}

// Function that runs a "sleep" process.
func generateEvent() (int, error) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		return 0, fmt.Errorf("running command: %w", err)
	}

	return cmd.Process.Pid, nil
}
