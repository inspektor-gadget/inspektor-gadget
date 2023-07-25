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

//go:build linux
// +build linux

package tracer_test

import (
	"errors"
	"fmt"
	"os"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func TestSignalTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	require.NotNil(t, tracer, "Returned tracer was nil")
}

func TestSignalTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

func TestSignalTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const unprivilegedUID = int(1435)
	const unprivilegedGID = int(6789)

	type testDefinition struct {
		getTracerConfig func(info *utilstest.RunnerInfo) *tracer.Config
		runnerConfig    *utilstest.RunnerConfig
		signalToSend    syscall.Signal
		generateEvent   func(syscall.Signal) (uint32, error)
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, childPid uint32, events []types.Event)
	}

	tests := map[string]testDefinition{
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			signalToSend:  syscall.SIGKILL,
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, childPid uint32) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(info.Pid),
					Comm:          path.Base(os.Args[0]),
					Signal:        unix.SignalName(syscall.SIGKILL),
					TargetPid:     childPid,
					Retval:        0,
					Uid:           uint32(info.Uid),
					Gid:           uint32(info.Gid),
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
				}
			}),
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig: &utilstest.RunnerConfig{
				Uid: unprivilegedUID,
				Gid: unprivilegedGID,
			},
			signalToSend:  syscall.SIGKILL,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ uint32, events []types.Event) {
				require.Len(t, events, 1, "One event expected")
				require.Equal(t, uint32(info.Uid), events[0].Uid, "Event has bad UID")
				require.Equal(t, uint32(info.Gid), events[0].Gid, "Event has bad GID")
			},
		},
		"generate_SIGSEGV": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func(_ syscall.Signal) (uint32, error) {
				// Use clone to make it more portable, at least for amd64 and arm64.
				childPid, _, errno := syscall.Syscall6(syscall.SYS_CLONE, uintptr(syscall.SIGCHLD), 0, 0, 0, 0, 0)
				if errno != 0 {
					var err error = errno

					return 0, fmt.Errorf("spawning child process: %w", err)
				}

				if childPid == 0 {
					var t *testDefinition
					t.signalToSend = 0xdead

					return 0, errors.New("this code should never be reached")
				}

				proc, err := os.FindProcess(int(childPid))
				if err != nil {
					return 0, fmt.Errorf("no process with PID %d: %w", childPid, err)
				}

				_, err = proc.Wait()
				if err != nil {
					return 0, fmt.Errorf("waiting child with PID %d: %w", childPid, err)
				}

				return uint32(childPid), nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, childPid uint32) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           childPid,
					Comm:          path.Base(os.Args[0]),
					Signal:        unix.SignalName(syscall.SIGSEGV),
					TargetPid:     childPid,
					Retval:        0,
					Uid:           uint32(info.Uid),
					Gid:           uint32(info.Gid),
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
				}
			}),
		},
	}

	for sig := syscall.SIGABRT; sig <= syscall.SIGXFSZ; sig++ {
		signal := sig
		tests[fmt.Sprintf("send_%s", unix.SignalName(signal))] = testDefinition{
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			signalToSend:  signal,
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, childPid uint32) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(info.Pid),
					Comm:          path.Base(os.Args[0]),
					Signal:        unix.SignalName(signal),
					TargetPid:     childPid,
					Retval:        0,
					Uid:           uint32(info.Uid),
					Gid:           uint32(info.Gid),
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
				}
			}),
		}
	}

	for name, test := range tests {
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

			var childPid uint32

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				childPid, err = test.generateEvent(test.signalToSend)
				return err
			})

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, runner.Info, childPid, events)
		})
	}
}

func createTracer(
	t *testing.T, config *tracer.Config, callback func(*types.Event),
) *tracer.Tracer {
	t.Helper()

	tracer, err := tracer.NewTracer(config, nil, callback)
	require.Nil(t, err, "Error creating tracer: %s", err)
	t.Cleanup(tracer.Stop)

	return tracer
}

func generateEvent(signal syscall.Signal) (uint32, error) {
	childPid, err := syscall.ForkExec("/bin/sleep", []string{"inf"}, nil)
	if err != nil {
		return 0, fmt.Errorf("spawning child process: %w", err)
	}

	// We only test kill and not tkill or tgkill as this is a pain to deal with
	// pthread in golang.
	err = syscall.Kill(childPid, signal)
	if err != nil {
		return 0, fmt.Errorf("sending signal %d to process %d: %w", signal, childPid, err)
	}

	return uint32(childPid), nil
}
