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
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
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
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	argv           []string
	runFromThread  bool
	validate       func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string)
}

func TestTraceExecGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"simple_executable": {
			runnerConfig: &utilstest.RunnerConfig{},
			argv:         []string{"/bin/echo", "hello", "world"},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, " ")
				require.Equal(t, expectedArgs, events[0].Args, "Expected Args %q, got %q", expectedArgs, events[0].Args)
			},
		},
		"large_argument_list": {
			runnerConfig: &utilstest.RunnerConfig{},
			// should only capture TOTAL_ARGS_SIZE ~ 20 arguments
			argv: []string{"/bin/echo", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9", "arg10", "arg11", "arg12", "arg13", "arg14", "arg15", "arg16", "arg17", "arg18", "arg19", "arg20", "arg21"},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs[:20], " ")
				require.Equal(t, expectedArgs, events[0].Args, "Expected Args %q, got %q", expectedArgs, events[0].Args)
			},
		},
		"uid_gid": {
			runnerConfig: &utilstest.RunnerConfig{
				Uid:         1000,
				Gid:         1000,
				HostNetwork: false,
			},
			argv: []string{"/bin/ls", "-l", "/"},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, " ")
				require.Equal(t, expectedArgs, events[0].Args, "Expected Args %q, got %q", expectedArgs, events[0].Args)
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
		"mount_namespace_filter_blocked": {
			runnerConfig: &utilstest.RunnerConfig{},
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID+100)
			},
			argv: []string{"/bin/date"},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				utilstest.ExpectNoEvent(t, info, "Expected 0 events", events)
			},
		},
		"error": {
			runnerConfig: &utilstest.RunnerConfig{},
			argv:         []string{"/bin/foobar", "hello"},
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, " ")
				require.Equal(t, expectedArgs, events[0].Args, "Expected Args %q, got %q", expectedArgs, events[0].Args)
				require.Equal(t, "ENOENT", events[0].Error)
			},
		},
		"successful_exec_from_thread": {
			runnerConfig:  &utilstest.RunnerConfig{},
			argv:          []string{"/bin/echo", "hello", "world"},
			runFromThread: true,
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 2, "Expected 2 events but got %d", len(events))
				require.Contains(t, events[0].Args, "/usr/bin/python3 -c")
				expectedArgs := strings.Join(inputArgs, " ")
				require.Equal(t, expectedArgs, events[1].Args, "Expected Args %q, got %q", expectedArgs, events[0].Args)
			},
		},
		"failed_exec_from_thread": {
			runnerConfig:  &utilstest.RunnerConfig{},
			argv:          []string{"/bin/meowmeow", "hello", "world"},
			runFromThread: true,
			validate: func(t *testing.T, info *utilstest.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 2, "Expected 2 events but got %d", len(events))
				require.Contains(t, events[0].Args, "/usr/bin/python3 -c")
				expectedArgs := strings.Join(inputArgs, " ")
				require.Equal(t, expectedArgs, events[1].Args, "Expected Args %q, got %q", expectedArgs, events[1].Args)
				require.Equal(t, "ENOENT", events[1].Error)
			},
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
					if testCase.runFromThread {
						generateEventFromThread(t, testCase.argv)
					} else {
						os.StartProcess(testCase.argv[0], testCase.argv, &os.ProcAttr{})
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceExecEvent]{
				Image:   "trace_exec",
				Timeout: 5 * time.Second,
				ParamValues: api.ParamValues{
					"operator.oci.ebpf.ignore-failed": "false",
				},
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			testCase.validate(t, runner.Info, gadgetRunner.CapturedEvents, testCase.argv)
		})
	}
}

func generateEventFromThread(t *testing.T, argv []string) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	args := "["
	for i, arg := range argv {
		if i > 0 {
			args += ", "
		}
		args += `"` + arg + `"`
	}
	args += "]"

	script := fmt.Sprintf(`
import threading
import os

def exec():
    os.execve("%s", %v, {})

def main():
    thread = threading.Thread(target=exec)
    thread.start()
    thread.join()

if __name__ == "__main__":
    main()
`, argv[0], args)
	cmd := exec.Command("python3", "-c", script)
	err := cmd.Run()
	if err != nil {
		// python3 is not available
		t.Skip("Skipping test, python3 is needed to run the test")
	}
}
