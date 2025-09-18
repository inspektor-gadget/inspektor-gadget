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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// This test file checks that the common filtering logic works as expected. We
// could have implemented a specific gadget for this test but it's an overkill
// as trace_open can be used.

type filterTestDef struct {
	// The following are tri state fields:
	// - nil: filter not used
	// - true: filter match
	// - false: filter not match

	matchMntns *bool
	matchPid   *bool
	matchTid   *bool
	matchUid   *bool
	matchGid   *bool
	matchComm  *bool
}

func genName(testCase filterTestDef) string {
	var name string

	if testCase.matchMntns != nil {
		name += fmt.Sprintf("mntns=%v,", *testCase.matchMntns)
	}
	if testCase.matchPid != nil {
		name += fmt.Sprintf("pid=%v,", *testCase.matchPid)
	}
	if testCase.matchTid != nil {
		name += fmt.Sprintf("tid=%v,", *testCase.matchTid)
	}
	if testCase.matchUid != nil {
		name += fmt.Sprintf("uid=%v,", *testCase.matchUid)
	}
	if testCase.matchGid != nil {
		name += fmt.Sprintf("gid=%v,", *testCase.matchGid)
	}
	if testCase.matchComm != nil {
		name += fmt.Sprintf("comm=%v,", *testCase.matchComm)
	}

	return name
}

func TestFiltering(t *testing.T) {
	trueVal := true
	falseVal := false

	gadgettesting.InitUnitTest(t)
	testCases := []filterTestDef{
		// no filter
		{},
		// one matching enabled at the time
		{
			matchMntns: &trueVal,
		},
		{
			matchPid: &trueVal,
		},
		{
			matchTid: &trueVal,
		},
		{
			matchUid: &trueVal,
		},
		{
			matchGid: &trueVal,
		},
		{
			matchComm: &trueVal,
		},
		// one non matching enabled at the time
		{
			matchMntns: &falseVal,
		},
		{
			matchPid: &falseVal,
		},
		{
			matchTid: &falseVal,
		},
		{
			matchUid: &falseVal,
		},
		{
			matchGid: &falseVal,
		},
		{
			matchComm: &falseVal,
		},
		// all matching
		{
			matchMntns: &trueVal,
			matchPid:   &trueVal,
			matchTid:   &trueVal,
			matchUid:   &trueVal,
			matchGid:   &trueVal,
			matchComm:  &trueVal,
		},
		// all non matching
		{
			matchMntns: &falseVal,
			matchPid:   &falseVal,
			matchTid:   &falseVal,
			matchUid:   &falseVal,
			matchGid:   &falseVal,
			matchComm:  &falseVal,
		},
		// all matching except one
		{
			matchMntns: &trueVal,
			matchPid:   &trueVal,
			matchTid:   &trueVal,
			matchUid:   &trueVal,
			matchGid:   &trueVal,
			matchComm:  &falseVal,
		},
		{
			matchMntns: &trueVal,
			matchPid:   &trueVal,
			matchTid:   &trueVal,
			matchUid:   &trueVal,
			matchGid:   &falseVal,
			matchComm:  &trueVal,
		},
		{
			matchMntns: &trueVal,
			matchPid:   &trueVal,
			matchTid:   &trueVal,
			matchUid:   &falseVal,
			matchGid:   &trueVal,
			matchComm:  &trueVal,
		},
		{
			matchMntns: &trueVal,
			matchPid:   &trueVal,
			matchTid:   &falseVal,
			matchUid:   &trueVal,
			matchGid:   &trueVal,
			matchComm:  &trueVal,
		},
		{
			matchMntns: &trueVal,
			matchPid:   &falseVal,
			matchTid:   &trueVal,
			matchUid:   &trueVal,
			matchGid:   &trueVal,
			matchComm:  &trueVal,
		},
		{
			matchMntns: &falseVal,
			matchPid:   &trueVal,
			matchTid:   &trueVal,
			matchUid:   &trueVal,
			matchGid:   &trueVal,
			matchComm:  &trueVal,
		},
	}

	for _, testCase := range testCases {
		t.Run(genName(testCase), func(t *testing.T) {
			t.Parallel()

			var mntnsFilterMap *ebpf.Map
			params := map[string]string{}
			expectedEvents := 1

			runnerConfig := &utils.RunnerConfig{
				Uid: 123456,
				Gid: 789012,
			}

			runner := utils.NewRunnerWithTest(t, runnerConfig)

			if testCase.matchMntns != nil {
				if *testCase.matchMntns {
					mntnsFilterMap = utils.CreateMntNsFilterMap(t, runner.Info.MountNsID)
				} else {
					mntnsFilterMap = utils.CreateMntNsFilterMap(t, 0)
					expectedEvents = 0
				}
			}
			if testCase.matchPid != nil {
				if *testCase.matchPid {
					params["operator.oci.ebpf.pid"] = fmt.Sprintf("%d", runner.Info.Proc.Pid)
				} else {
					params["operator.oci.ebpf.pid"] = fmt.Sprintf("%d", runner.Info.Proc.Pid+50)
					expectedEvents = 0
				}
			}
			if testCase.matchTid != nil {
				if *testCase.matchTid {
					params["operator.oci.ebpf.tid"] = fmt.Sprintf("%d", runner.Info.Proc.Tid)
				} else {
					params["operator.oci.ebpf.tid"] = fmt.Sprintf("%d", runner.Info.Proc.Tid+50)
					expectedEvents = 0
				}
			}
			if testCase.matchUid != nil {
				if *testCase.matchUid {
					params["operator.oci.ebpf.uid"] = fmt.Sprintf("%d", runner.Info.Uid)
				} else {
					params["operator.oci.ebpf.uid"] = fmt.Sprintf("%d", runner.Info.Uid+50)
					expectedEvents = 0
				}
			}
			if testCase.matchGid != nil {
				if *testCase.matchGid {
					params["operator.oci.ebpf.gid"] = fmt.Sprintf("%d", runner.Info.Gid)
				} else {
					params["operator.oci.ebpf.gid"] = fmt.Sprintf("%d", runner.Info.Gid+50)
					expectedEvents = 0
				}
			}
			if testCase.matchComm != nil {
				if *testCase.matchComm {
					params["operator.oci.ebpf.comm"] = runner.Info.Proc.Comm
				} else {
					params["operator.oci.ebpf.comm"] = runner.Info.Proc.Comm[:len(runner.Info.Proc.Comm)-1]
					expectedEvents = 0
				}
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
				utils.RunWithRunner(t, runner, func() error {
					return generateEventWithSpecificPath(tmpPath)
				})
				return nil
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceOpenEvent]{
				Image:          "trace_open",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
				ParamValues:    params,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			require.Equal(t, expectedEvents, countEvents(tmpPath, gadgetRunner.CapturedEvents))
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
