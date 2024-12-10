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
	"os"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

// This test file checks that the common filtering logic works as expected. We
// could have implemented a specific gadget for this test but it's an overkill
// as trace_open can be used.

type filterTestDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	params         func(t *testing.T, info *utilstest.RunnerInfo) map[string]string
	expectedEvents int
}

func TestFiltering(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]filterTestDef{
		"filter_by_mntns_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{}
			},
			expectedEvents: 1,
		},
		"filter_by_mntns_no_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, 0)
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{}
			},
			expectedEvents: 0,
		},
		"filter_by_pid_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.pid": fmt.Sprintf("%d", info.Proc.Pid),
				}
			},
			expectedEvents: 1,
		},
		"filter_by_pid_no_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.pid": "1",
				}
			},
			expectedEvents: 0,
		},
		"filter_by_tid_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.tid": fmt.Sprintf("%d", info.Proc.Tid),
				}
			},
			expectedEvents: 1,
		},
		"filter_by_tid_no_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.tid": "1",
				}
			},
			expectedEvents: 0,
		},
		"filter_by_uid_match": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid: 123456,
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.uid": "123456",
				}
			},
			expectedEvents: 1,
		},
		"filter_by_uid_no_match": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid: 123456,
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.uid": "0",
				}
			},
			expectedEvents: 0,
		},
		"filter_by_gid_match": {
			runnerConfig: &utilstest.RunnerConfig{
				Gid: 123456,
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.gid": "123456",
				}
			},
			expectedEvents: 1,
		},
		"filter_by_gid_no_match": {
			runnerConfig: &utilstest.RunnerConfig{
				Gid: 123456,
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.gid": "0",
				}
			},
			expectedEvents: 0,
		},
		"filter_by_comm_match": {
			runnerConfig: &utilstest.RunnerConfig{},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.comm": info.Proc.Comm,
				}
			},
			expectedEvents: 1,
		},
		"filter_by_comm_no_match": {
			runnerConfig: &utilstest.RunnerConfig{
				Gid: 123456,
			},
			params: func(t *testing.T, info *utilstest.RunnerInfo) map[string]string {
				return map[string]string{
					"operator.oci.ebpf.comm": info.Proc.Comm[:len(info.Proc.Comm)-1],
				}
			},
			expectedEvents: 0,
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}

			// t.TempDir() is more difficult to use here as it creates a
			// subfolder and we'll need to call os.Chown recursively on it.
			f, err := os.CreateTemp("", "filter-test")
			t.Cleanup(func() {
				os.Remove(f.Name())
			})
			require.NoError(t, err)
			tmpPath := f.Name()
			require.NoError(t, os.Chown(tmpPath, runner.Info.Uid, runner.Info.Gid))

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					return generateEventWithSpecificPath(tmpPath)
				})
				return nil
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceOpenEvent]{
				Image:          "trace_open",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
				ParamValues:    testCase.params(t, runner.Info),
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			require.Equal(t, testCase.expectedEvents, countEvents(tmpPath, gadgetRunner.CapturedEvents))
		})
	}
}

// generateEvent simulates an event by opening and closing a file
func generateEventWithSpecificPath(path string) error {
	fd, err := unix.Open(path, 0, 0)
	if err != nil {
		return err
	}

	// Close the file descriptor to simulate the event
	return unix.Close(fd)
}

func countEvents(path string, events []ExpectedTraceOpenEvent) int {
	count := 0
	for _, event := range events {
		if event.FName == path {
			count++
		}
	}
	return count
}
