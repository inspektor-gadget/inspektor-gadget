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
	"fmt"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetapi"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceOpenEvent struct {
	Comm  string `json:"comm"`
	Pid   uint32 `json:"pid"`
	Tid   uint32 `json:"tid"`
	Uid   uint32 `json:"uid"`
	Gid   uint32 `json:"gid"`
	Fd    uint32 `json:"fd"`
	FName string `json:"fname"`
}

type testDef struct {
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (int, error)
	expectedEntry *ExpectedTraceOpenEvent
	normalize     func(e *ExpectedTraceOpenEvent)
}

func TestTraceOpenGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	testCases := map[string]testDef{
		"testcase1": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			expectedEntry: &ExpectedTraceOpenEvent{
				Comm:  "unit.test",
				Pid:   utils.NormalizedInt,
				Tid:   utils.NormalizedInt,
				Uid:   0,
				Gid:   0,
				Fd:    utils.NormalizedInt,
				FName: "/dev/null",
			},
			normalize: func(e *ExpectedTraceOpenEvent) {
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.Fd)
			},
		},
		"testcase2": {
			runnerConfig: &utilstest.RunnerConfig{},
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
			expectedEntry: &ExpectedTraceOpenEvent{
				Comm:  "unit.test",
				Pid:   utils.NormalizedInt,
				Tid:   utils.NormalizedInt,
				Uid:   0,
				Gid:   0,
				Fd:    utils.NormalizedInt,
				FName: "/tmp/foo.test",
			},
			normalize: func(e *ExpectedTraceOpenEvent) {
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.Fd)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			timeout := 10 * time.Second
			api, _ := gadgetapi.NewGadget("ghcr.io/inspektor-gadget/gadget/trace_open:latest", timeout)
			params := map[string]string{
				"operator.oci.ebpf.uid": "0",
			}

			api.StartGadget(params)
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			utilstest.RunWithRunner(t, runner, func() error {
				testCase.generateEvent()
				// Wait for the event to be processed
				time.Sleep(1 * time.Second)
				output := api.Output()
				match.MatchEntries(t, match.JSONSingleArrayMode, string(output), testCase.normalize, testCase.expectedEntry)
				return nil
			})
		})
	}
}

// generateEvent simulates an event by opening and closing a file
func generateEvent() (int, error) {
	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return 0, fmt.Errorf("opening file: %w", err)
	}

	// Close the file descriptor to simulate the event
	if err := unix.Close(fd); err != nil {
		return 0, fmt.Errorf("closing file: %w", err)
	}

	return fd, nil
}
