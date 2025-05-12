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
	"fmt"
	"os"
	"os/exec"
	"path"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type execResult struct {
	CatPid int
	Ptid   int
}

func TestExecTracerCreate(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})
	require.NotNil(t, tracer, "Returned tracer was nil")
}

func TestExecTracerStopIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer(t, &tracer.Config{}, func(*types.Event) {})

	// Check that a double stop doesn't cause issues
	tracer.Stop()
	tracer.Stop()
}

func TestExecTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const unprivilegedUID = int(1435)
	const unprivilegedGID = int(6789)

	manyArgs := []string{}
	// 19 is DEFAULT_MAXARGS - 1 (-1 because args[0] is on the first position).
	for i := 0; i < 19; i++ {
		manyArgs = append(manyArgs, "/dev/null")
	}

	cwd, err := os.Getwd()
	require.Nil(t, err, "Failed to get current working directory: %s", err)

	executable, err := os.Executable()
	require.Nil(t, err, "Failed to get executable path: %s", err)
	pcomm := path.Base(executable)

	type testDefinition struct {
		shouldSkip      func(t *testing.T)
		getTracerConfig func(info *utilstest.RunnerInfo) *tracer.Config
		runnerConfig    *utilstest.RunnerConfig
		generateEvent   func() (execResult, error)
		validateEvent   func(t *testing.T, info *utilstest.RunnerInfo, execResult execResult, events []types.Event)
	}

	loginuid := utilstest.ReadFileAsUint32(t, "/proc/self/loginuid")
	sessionid := utilstest.ReadFileAsUint32(t, "/proc/self/sessionid")

	for name, test := range map[string]testDefinition{
		"captures_all_events_with_no_filters_configured": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, execResult execResult) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(execResult.CatPid),
					Tid:           uint32(execResult.CatPid),
					Ppid:          uint32(info.Pid),
					Ptid:          uint32(execResult.Ptid),
					Uid:           uint32(info.Uid),
					LoginUid:      loginuid,
					SessionId:     sessionid,
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Retval:        0,
					Comm:          "cat",
					Pcomm:         pcomm,
					Args:          []string{"/bin/cat", "/dev/null"},
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
			validateEvent: utilstest.ExpectNoEvent[types.Event, execResult],
		},
		"captures_events_with_matching_filter": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: generateEvent,
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, execResult execResult) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Pid:           uint32(execResult.CatPid),
					Tid:           uint32(execResult.CatPid),
					Ppid:          uint32(info.Pid),
					Ptid:          uint32(execResult.Ptid),
					Uid:           uint32(info.Uid),
					LoginUid:      loginuid,
					SessionId:     sessionid,
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Retval:        0,
					Comm:          "cat",
					Pcomm:         pcomm,
					Args:          []string{"/bin/cat", "/dev/null"},
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
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				require.Len(t, events, 1, "One event expected")
				require.Equal(t, uint32(info.Uid), events[0].Uid, "Event has bad UID")
				require.Equal(t, uint32(info.Gid), events[0].Gid, "Event has bad GID")
			},
		},
		"truncates_captured_args_in_trace_to_maximum_possible_length": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func() (execResult, error) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				args := append(manyArgs, "/dev/null")
				cmd := exec.Command("/bin/cat", args...)
				if err := cmd.Run(); err != nil {
					return execResult{
						CatPid: 0,
						Ptid:   0,
					}, fmt.Errorf("running command: %w", err)
				}

				ptid := unix.Gettid()

				return execResult{
					CatPid: cmd.Process.Pid,
					Ptid:   ptid,
				}, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				require.Len(t, events, 1, "One event expected")
				require.Equal(t, append([]string{"/bin/cat"}, manyArgs...), events[0].Args, "Event has bad args")
			},
		},
		"event_has_correct_paths": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					GetPaths:   true,
				}
			},
			generateEvent: func() (execResult, error) {
				runtime.LockOSThread()
				defer runtime.UnlockOSThread()

				args := append(manyArgs, "/dev/null")
				cmd := exec.Command("/bin/cat", args...)
				if err := cmd.Run(); err != nil {
					return execResult{
						CatPid: 0,
						Ptid:   0,
					}, fmt.Errorf("running command: %w", err)
				}

				ptid := unix.Gettid()

				return execResult{
					CatPid: cmd.Process.Pid,
					Ptid:   ptid,
				}, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				require.Len(t, events, 1, "One event expected")
				require.Equal(t, events[0].Cwd, cwd, "Event has bad cwd")
				// Depending on the Linux distribution, /bin can be a symlink to /usr/bin
				exepath := strings.TrimPrefix(events[0].ExePath, "/usr")
				require.Equal(t, exepath, "/bin/cat", "Event has bad exe path")
			},
		},
		"event_failed": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: generateFailedEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				require.Len(t, events, 1, "One event expected")
				require.Equal(t, []string{"/bin/foobar"}, events[0].Args, "Event has bad args")
				require.NotEqual(t, int(0), events[0].Retval, "Event returns 0, while it should return an error code")
			},
		},
		"event_failed_ignored": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap:   utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					IgnoreErrors: true,
				}
			},
			generateEvent: generateFailedEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				require.Len(t, events, 0, "Zero events expected")
			},
		},
		"event_from_non_main_thread_success": {
			shouldSkip: func(t *testing.T) {
				if _, err := exec.LookPath("python3"); err != nil {
					t.Skip("Python3 not found")
				}
			},
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig: &utilstest.RunnerConfig{
				Uid: unprivilegedUID,
				Gid: unprivilegedGID,
			},
			generateEvent: generateEventFromThread(true),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				// python + cat
				require.Len(t, events, 2, "Two events expected")
				require.Equal(t, "python3", events[0].Comm, "Event has bad comm")
				require.Equal(t, 0, events[0].Retval, "Event has bad retval")
				require.Equal(t, "cat", events[1].Comm, "Event has bad comm")
				require.Equal(t, 0, events[1].Retval, "Event has bad retval")
			},
		},
		"event_from_non_main_thread_fail": {
			shouldSkip: func(t *testing.T) {
				if _, err := exec.LookPath("python3"); err != nil {
					t.Skip("Python3 not found")
				}
			},
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			runnerConfig: &utilstest.RunnerConfig{
				Uid: unprivilegedUID,
				Gid: unprivilegedGID,
			},
			generateEvent: generateEventFromThread(false),
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ execResult, events []types.Event) {
				// python + cat
				require.Len(t, events, 2, "Two events expected")
				require.Equal(t, "python3", events[0].Comm, "Event has bad comm")
				require.Equal(t, 0, events[0].Retval, "Event has bad retval")
				require.Equal(t, "python3", events[1].Comm, "Event has bad comm")
				require.Equal(t, -int(unix.ENOENT), events[1].Retval, "Event has bad retval")
			},
		},
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if test.shouldSkip != nil {
				test.shouldSkip(t)
			}

			events := []types.Event{}
			eventCallback := func(event *types.Event) {
				// normalize
				event.Timestamp = 0

				events = append(events, *event)
			}

			runner := utilstest.NewRunnerWithTest(t, test.runnerConfig)

			createTracer(t, test.getTracerConfig(runner.Info), eventCallback)

			var result execResult

			utilstest.RunWithRunner(t, runner, func() error {
				var err error
				result, err = test.generateEvent()
				return err
			})

			// Give some time for the tracer to capture the events
			time.Sleep(100 * time.Millisecond)

			test.validateEvent(t, runner.Info, result, events)
		})
	}
}

func TestExecTracerMultipleMntNsIDsFilter(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	events := []types.Event{}
	eventCallback := func(event *types.Event) {
		// normalize
		event.Timestamp = 0

		events = append(events, *event)
	}

	// struct with only fields we want to check on this test
	type expectedEvent struct {
		mntNsID uint64
		catPid  int
		Ptid    int
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
			var result execResult
			result, err = generateEvent()
			expectedEvents[i].catPid, expectedEvents[i].Ptid = result.CatPid, result.Ptid

			return err
		})
	}

	// Give some time for the tracer to capture the events
	time.Sleep(100 * time.Millisecond)

	require.Len(t, events, n-1)

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
		require.Equal(t, expectedEvents[i].mntNsID, events[i].MountNsID,
			"Captured event has bad MountNsID")

		require.Equal(t, uint32(expectedEvents[i].catPid), events[i].Pid,
			"Captured event has bad PID")
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

// Function to generate an event used most of the times.
// Returns pid of executed process.
func generateEvent() (execResult, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	cmd := exec.Command("/bin/cat", "/dev/null")
	if err := cmd.Run(); err != nil {
		return execResult{
			CatPid: 0,
			Ptid:   0,
		}, fmt.Errorf("running command: %w", err)
	}

	ptid := unix.Gettid()

	return execResult{
		CatPid: cmd.Process.Pid,
		Ptid:   ptid,
	}, nil
}

// Function to generate a failed event.
// Return 0 as no process is created.
func generateFailedEvent() (execResult, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Ignore error since we want to capture a failed event
	exec.Command("/bin/foobar").Run()
	return execResult{
		CatPid: 0,
		Ptid:   0,
	}, nil
}

// Function to generate an exec() event from a thread.
func generateEventFromThread(success bool) func() (execResult, error) {
	return func() (execResult, error) {
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()

		bin := "/bin/cat"
		if !success {
			bin = "/bin/NONE"
		}
		script := fmt.Sprintf(`
import threading
import os

def exec():
    os.execve("%s", ["cat", "/dev/null"], {})

def main():
    thread = threading.Thread(target=exec)
    thread.start()
    thread.join()

if __name__ == "__main__":
    main()
`, bin)
		cmd := exec.Command("python3", "-c", script)
		if err := cmd.Run(); err != nil {
			return execResult{
				CatPid: 0,
				Ptid:   0,
			}, fmt.Errorf("running command: %w", err)
		}

		ptid := unix.Gettid()

		return execResult{
			CatPid: cmd.Process.Pid,
			Ptid:   ptid,
		}, nil
	}
}
