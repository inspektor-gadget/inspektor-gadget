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
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	igjson "github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/simple"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

type ExpectedTraceOpenEvent struct {
	Comm  string `json:"comm"`
	Pid   int    `json:"pid"`
	Tid   int    `json:"tid"`
	Uid   uint32 `json:"uid"`
	Gid   uint32 `json:"gid"`
	Fd    uint32 `json:"fd"`
	FName string `json:"fname"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (int, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"captures_all_events": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func() (int, error) {
				return generateEvent(t)
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  "unit.test",
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/dev/null",
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"test_symbolic_links": {
			runnerConfig: &utilstest.RunnerConfig{},
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
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  "unit.test",
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/tmp/test_symbolic_links",
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"test_relative_path": {
			runnerConfig: &utilstest.RunnerConfig{},
			generateEvent: func() (int, error) {
				relPath := generateRelativePathForAbsolutePath(t, "/tmp/test_relative_path")
				fd, err := unix.Open(relPath, unix.O_CREAT|unix.O_RDWR, unix.S_IRWXU|unix.S_IRGRP|unix.S_IWGRP|unix.S_IXOTH)
				require.NoError(t, err, "opening file")

				defer os.Remove(relPath)

				unix.Close(fd)

				return fd, nil
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  "unit.test",
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "../../../../../../../tmp/test_relative_path",
					}
				})(t, info, fd, events)
				return nil
			},
		},
		"test_prefix_on_directory": {
			runnerConfig: &utilstest.RunnerConfig{},
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
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, fd int, events []ExpectedTraceOpenEvent) error {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedTraceOpenEvent {
					return &ExpectedTraceOpenEvent{
						Comm:  "unit.test",
						Pid:   info.Pid,
						Tid:   info.Tid,
						Uid:   uint32(info.Uid),
						Gid:   uint32(info.Gid),
						Fd:    uint32(fd),
						FName: "/tmp/foo/bar.test",
					}
				})(t, info, fd, events)
				return nil
			}},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			capturedEvents := []ExpectedTraceOpenEvent{}
			var fd int
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			timeout := 5 * time.Second
			const opPriority = 50000

			gadgetOperator := simple.New("gadget",
				// On init, subscribe to the data sources
				simple.OnInit(func(gadgetCtx operators.GadgetContext) error {
					for _, d := range gadgetCtx.GetDataSources() {
						jsonFormatter, _ := igjson.New(d)
						d.Subscribe(func(source datasource.DataSource, data datasource.Data) error {
							event := &ExpectedTraceOpenEvent{}
							jsonOutput := jsonFormatter.Marshal(data)
							err := json.Unmarshal(jsonOutput, event)
							require.NoError(t, err, "unmarshalling event")

							// for current reference of the event
							fmt.Println("Captured data: ", string(jsonOutput))

							capturedEvents = append(capturedEvents, *event)

							return nil
						}, opPriority)

					}
					return nil
				}),
				// On start, generate an event that can be captured
				simple.OnStart(func(gadgetCtx operators.GadgetContext) error {
					utilstest.RunWithRunner(t, runner, func() error {
						fd, _ = testCase.generateEvent()
						return nil
					})
					return nil
				}))

			gadgetCtx := gadgetcontext.New(
				context.Background(),
				// Use the trace_open gadget, this part will be made more modular in the future
				"ghcr.io/inspektor-gadget/gadget/trace_open:latest",
				gadgetcontext.WithDataOperators(
					ocihandler.OciHandler,
					gadgetOperator,
				),
				gadgetcontext.WithTimeout(timeout),
			)
			runtime := local.New()
			err := runtime.Init(nil)
			require.NoError(t, err, "initializing runtime")
			params := map[string]string{
				// Filter only events from the root user
				"operator.oci.ebpf.uid": "0",
			}

			err = runtime.RunGadget(gadgetCtx, nil, params)
			require.NoError(t, err, "running gadget")

			// Wait for the gadget to finish and then validate the events
			testCase.validateEvent(t, runner.Info, fd, capturedEvents)
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
func generateEvent(t *testing.T) (int, error) {
	fd, err := unix.Open("/dev/null", 0, 0)
	require.NoError(t, err, "opening file")

	// Close the file descriptor to simulate the event
	err = unix.Close(fd)
	require.NoError(t, err, "closing file")

	return fd, nil
}
