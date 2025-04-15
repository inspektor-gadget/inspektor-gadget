// Copyright 2025 The Inspektor Gadget authors
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
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceExecEvent struct {
	Proc  utils.Process `json:"proc"`
	Error string        `json:"error"`
	Args  string        `json:"args"`
}

type testDef struct {
	runnerConfig         *utilstest.RunnerConfig
	mntnsFilterMap       func(info *utilstest.RunnerInfo) *ebpf.Map
	argv                 []string
	eventsBlocked        bool
	additionalValidation func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent)
}

func TestTraceExecGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"simple_executable": {
			runnerConfig: &utilstest.RunnerConfig{},
			argv:         []string{"/bin/echo", "hello", "world"},
		},
		"large_argument_list": {
			runnerConfig: &utilstest.RunnerConfig{},
			// should only capture TOTAL_ARGS_SIZE ~ 20 arguments
			argv: []string{"/bin/echo", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9", "arg10", "arg11", "arg12", "arg13", "arg14", "arg15", "arg16", "arg17", "arg18", "arg19", "arg20", "arg21"},
		},
		"custom_runner_config": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid:         1000,
				Gid:         1000,
				HostNetwork: false,
			},
			argv: []string{"/bin/ls", "-l", "/"},
			additionalValidation: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent) {
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
		"mount_namespace_filter_blocked": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID+1)
			},
			argv:          []string{"/bin/date"},
			eventsBlocked: true,
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap == nil {
				// by default we use the mount namespace of the runner
				mntnsFilterMap = utilstest.CreateMntNsFilterMap(t, runner.Info.MountNsID)
			} else {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					_, err := func() (int, error) {
						_, err := os.StartProcess(testCase.argv[0], testCase.argv, &os.ProcAttr{})
						return 0, err
					}()
					return err
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceExecEvent]{
				Image:          "trace_exec",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			if testCase.eventsBlocked {
				if len(gadgetRunner.CapturedEvents) != 0 {
					t.Fatalf("Expected no events but got %d", len(gadgetRunner.CapturedEvents))
				} else {
					return
				}
			}

			if len(gadgetRunner.CapturedEvents) != 1 {
				t.Fatalf("Expected 1 event but got %d", len(gadgetRunner.CapturedEvents))
			}
			ev := gadgetRunner.CapturedEvents[0]

			// can only capture TOTAL_ARGS_SIZE ~ 20 arguments
			if len(testCase.argv) > 20 {
				testCase.argv = testCase.argv[:20]
			}
			expectedArgs := strings.Join(testCase.argv, " ")

			if ev.Args != expectedArgs {
				t.Errorf("Expected Args %q, got %q", expectedArgs, ev.Args)
			}

			if testCase.additionalValidation != nil {
				testCase.additionalValidation(t, runner.Info, gadgetRunner.CapturedEvents)
			}
		})
	}
}
