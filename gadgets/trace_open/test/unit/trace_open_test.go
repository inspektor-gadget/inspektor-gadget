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

package tests

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type ExpectedTraceOpenEvent struct {
	Comm     string `json:"comm"`
	Pid      int    `json:"pid"`
	Tid      int    `json:"tid"`
	Uid      uint32 `json:"uid"`
	Gid      uint32 `json:"gid"`
	Fd       uint32 `json:"fd"`
	FName    string `json:"fname"`
	FlagsRaw int    `json:"flags_raw"`
	ModeRaw  int    `json:"mode_raw"`
	ErrRaw   int    `json:"error_raw"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	generateEvent  func() (int, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent)
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  info.Comm,
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectNoEvent(t, info, fd, events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  info.Comm,
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
			},
		},
		"test_flags_and_mode": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: func() (int, error) {
				filename := "/tmp/test_flags_and_mode"
				fd, err := unix.Open(filename, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				if err != nil {
					return 0, err
				}
				defer os.Remove(filename)
				unix.Close(fd)

				return fd, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, events[0].ModeRaw, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH, "mode")
				require.Equal(t, events[0].FlagsRaw, unix.O_CREAT|unix.O_RDWR, "flags")
			},
		},
		"test_symbolic_links": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: func() (int, error) {
				// Create a symbolic link to /dev/null
				err := os.Symlink("/dev/null", "/tmp/test_symbolic_links")
				if err != nil {
					return 0, err
				}

				defer os.Remove("/tmp/test_symbolic_links")

				// Open the symbolic link
				fd, err := unix.Open("/tmp/test_symbolic_links", unix.O_RDONLY, 0)
				if err != nil {
					return 0, err
				}

				defer unix.Close(fd)

				return fd, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, events[0].FName, "/tmp/test_symbolic_links", "filename")
			},
		},
		"test_relative_path": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: func() (int, error) {
				relPath := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				fd, err := unix.Open(relPath, unix.O_CREAT, 0)
				if err != nil {
					return 0, err
				}

				defer os.Remove(relPath)

				unix.Close(fd)

				return fd, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				require.Len(t, events, 1, "expected one event")
				relative_path := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				require.Equal(t, events[0].FName, relative_path, "filename")
			},
		},
		"test_prefix_on_directory": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func() (int, error) {
				err := os.Mkdir("/tmp/foo", 0o750)
				if err != nil {
					return 0, err
				}

				defer os.RemoveAll("/tmp/foo")

				fd, err := unix.Open("/tmp/foo/bar.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, err
				}

				defer unix.Close(fd)

				badfd, err := unix.Open("/tmp/quux.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, err
				}

				defer unix.Close(badfd)

				return fd, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:     info.Comm,
						Pid:      info.Pid,
						Tid:      info.Tid,
						Uid:      uint32(info.Uid),
						Gid:      uint32(info.Gid),
						Fd:       uint32(fd),
						FName:    "/tmp/foo/bar.test",
						ErrRaw:   0,
						FlagsRaw: unix.O_RDONLY | unix.O_CREAT,
						ModeRaw:  0,
					}
				})(t, info, fd, events)
			},
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid: int(1435),
				Gid: int(6789),
			},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ int, events []ExpectedTraceOpenEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, uint32(info.Uid), events[0].Uid)
				require.Equal(t, uint32(info.Gid), events[0].Gid)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var fd int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					fd, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceOpenEvent]{
				Image:          "trace_open",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, fd, gadgetRunner.CapturedEvents)
		})
	}
}

func generateRelativePathForAbsolutePath(t *testing.T, fileName string) string {
	// If the filename is relative, return it as is
	if !filepath.IsAbs(fileName) {
		return fileName
	}

	cwd, err := os.Getwd()
	require.NoError(t, err, "getting current working directory")

	relPath, err := filepath.Rel(cwd, fileName)
	require.NoError(t, err, "getting relative path")

	return relPath
}

// generateEvent simulates an event by opening and closing a file
func generateEvent() (int, error) {
	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return 0, err
	}

	// Close the file descriptor to simulate the event
	err = unix.Close(fd)
	if err != nil {
		return fd, err
	}

	return fd, nil
}
