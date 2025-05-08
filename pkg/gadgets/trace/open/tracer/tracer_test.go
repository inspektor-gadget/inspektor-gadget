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
	"path"
	"path/filepath"
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

func generateRelativePathForAbsolutePath(t *testing.T, fileName string) string {
	// If the filename is relative, return it as is
	if !filepath.IsAbs(fileName) {
		return fileName
	}

	cwd, err := os.Getwd()
	if err != nil {
		t.Errorf("Error getting current working directory: %s", err)
	}

	relPath, err := filepath.Rel(cwd, fileName)
	if err != nil {
		t.Errorf("Error getting relative path: %s", err)
	}

	return relPath
}

func generateLongDirPath(t *testing.T) string {
	pathNumber := 54
	str := "abcdefgh"
	slice := make([]string, pathNumber)
	for i := 0; i < pathNumber; i++ {
		slice[i] = str
	}

	// len("/tmp) + size * len("/" + str) = 4 + 54 * (1 + 8) = 490
	longPath := path.Join("/tmp", path.Join(slice...))

	// include/gadget/filesystem.h
	// #define GADGET_PATH_MAX    512
	if len(longPath) >= 512 {
		t.Fatalf("Generated long path is too long: %d", len(longPath))
	}
	return longPath
}

func TestOpenTracer(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const unprivilegedUID = int(1435)
	const unprivilegedGID = int(6789)

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
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/dev/null",
					Flags:         []string{"O_RDONLY"},
					Mode:          "----------",
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
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/dev/null",
					FullPath:      "",
					Flags:         []string{"O_RDONLY"},
					Mode:          "----------",
				}
			}),
		},
		"test_flags_and_mode": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
				}
			},
			generateEvent: func() (int, error) {
				filename := "/tmp/test_flags_and_mode"
				fd, err := unix.Open(filename, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}

				defer os.Remove(filename)

				unix.Close(fd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/tmp/test_flags_and_mode",
					FullPath:      "",
					Flags:         []string{"O_RDWR", "O_CREAT"},
					FlagsRaw:      unix.O_CREAT | unix.O_RDWR,
					Mode:          "-rwxrw---x",
					ModeRaw:       unix.S_IRWXU | unix.S_IRGRP | unix.S_IWGRP | unix.S_IXOTH,
				}
			}),
		},
		"test_relative_path": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					FullPath:   true,
				}
			},
			generateEvent: func() (int, error) {
				relPath := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				fd, err := unix.Open(relPath, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}

				defer os.Remove(relPath)

				unix.Close(fd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				relPath := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          relPath,
					FullPath:      "/tmp/test_relative_path",
					Flags:         []string{"O_RDWR", "O_CREAT"},
					FlagsRaw:      unix.O_CREAT | unix.O_RDWR,
					Mode:          "-rwxrw---x",
					ModeRaw:       unix.S_IRWXU | unix.S_IRGRP | unix.S_IWGRP | unix.S_IXOTH,
				}
			}),
		},
		"test_symbolic_links": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					FullPath:   true,
				}
			},
			generateEvent: func() (int, error) {
				// Create a symbolic link to /dev/null
				err := os.Symlink("/dev/null", "/tmp/test_symbolic_links")
				if err != nil {
					return 0, fmt.Errorf("creating symbolic link: %w", err)
				}
				defer os.Remove("/tmp/test_symbolic_links")

				// Open the symbolic link
				fd, err := unix.Open("/tmp/test_symbolic_links", unix.O_RDONLY, 0)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}
				defer unix.Close(fd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/tmp/test_symbolic_links",
					FullPath:      "/dev/null",
					Flags:         []string{"O_RDONLY"},
					Mode:          "----------",
				}
			}),
		},
		"test_long_path": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					FullPath:   true,
				}
			},
			generateEvent: func() (int, error) {
				dirPath := generateLongDirPath(t)
				err := os.MkdirAll(generateLongDirPath(t), 0o755)
				if err != nil {
					return 0, fmt.Errorf("creating directory: %w", err)
				}
				fd, err := unix.Open(path.Join(dirPath, "test_long_path"), unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}

				defer os.RemoveAll(path.Join(dirPath, "test_long_path"))

				unix.Close(fd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				longPath := path.Join(generateLongDirPath(t), "test_long_path")
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          longPath[:254],
					FullPath:      longPath,
					Flags:         []string{"O_RDWR", "O_CREAT"},
					FlagsRaw:      unix.O_CREAT | unix.O_RDWR,
					Mode:          "-rwxrw---x",
					ModeRaw:       unix.S_IRWXU | unix.S_IRGRP | unix.S_IWGRP | unix.S_IXOTH,
				}
			}),
		},
		"test_prefix_on_directory": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					Prefixes:   []string{"/tmp/foo"},
				}
			},
			generateEvent: func() (int, error) {
				err := os.Mkdir("/tmp/foo", 0o750)
				if err != nil {
					return 0, fmt.Errorf("creating directory: %w", err)
				}
				defer os.RemoveAll("/tmp/foo")

				fd, err := unix.Open("/tmp/foo/bar.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}
				defer unix.Close(fd)

				badfd, err := unix.Open("/tmp/quux.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}
				defer unix.Close(badfd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/tmp/foo/bar.test",
					Flags:         []string{"O_RDONLY", "O_CREAT"},
					FlagsRaw:      unix.O_RDONLY | unix.O_CREAT,
					Mode:          "----------",
				}
			}),
		},
		"test_prefix_on_file": {
			getTracerConfig: func(info *utilstest.RunnerInfo) *tracer.Config {
				return &tracer.Config{
					MountnsMap: utilstest.CreateMntNsFilterMap(t, info.MountNsID),
					Prefixes:   []string{"/tmp/foo.test"},
				}
			},
			generateEvent: func() (int, error) {
				fd, err := unix.Open("/tmp/foo.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}
				defer unix.Close(fd)

				badfd, err := unix.Open("/tmp/quux.test", unix.O_RDONLY|unix.O_CREAT, 0)
				if err != nil {
					return 0, fmt.Errorf("opening file: %w", err)
				}
				defer unix.Close(badfd)

				return fd, nil
			},
			validateEvent: utilstest.ExpectOneEvent(func(info *utilstest.RunnerInfo, fd int) *types.Event {
				return &types.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					WithMountNsID: eventtypes.WithMountNsID{MountNsID: info.MountNsID},
					Pid:           uint32(info.Pid),
					Tid:           uint32(info.Tid),
					Uid:           uint32(info.Uid),
					Comm:          info.Comm,
					Fd:            uint32(fd),
					Err:           0,
					Path:          "/tmp/foo.test",
					Flags:         []string{"O_RDONLY", "O_CREAT"},
					FlagsRaw:      unix.O_RDONLY | unix.O_CREAT,
					Mode:          "----------",
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
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, _ int, events []types.Event) {
				if len(events) != 1 {
					t.Fatalf("One event expected")
				}

				utilstest.Equal(t, uint32(info.Uid), events[0].Uid,
					"Captured event has bad UID")

				utilstest.Equal(t, uint32(info.Gid), events[0].Gid,
					"Captured event event has bad GID")
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

				utilstest.Equal(t, int(unix.ENOENT), int(events[0].Err),
					"Captured event has bad Err")
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
		fd      uint32
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
			fd, err := generateEvent()
			expectedEvents[i].fd = uint32(fd)
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
