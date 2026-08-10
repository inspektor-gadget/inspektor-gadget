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
	"syscall"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	traceexec "github.com/inspektor-gadget/inspektor-gadget/gadgets/trace_exec/consts"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceExecEvent struct {
	Proc     utils.Process `json:"proc"`
	Error    string        `json:"error"`
	Args     string        `json:"args"`
	Ctime    uint64        `json:"ctime"`
	Fctime   uint64        `json:"fctime"`
	Pctime   uint64        `json:"pctime"`
	Tty      int32         `json:"tty"`
	TtyMajor uint32        `json:"tty_major"`
	TtyMinor uint32        `json:"tty_minor"`
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
	argv           []string
	// execPath, when set, is the path passed to execve while argv is used as
	// the argument vector. It allows testing an argv[0] that differs from the
	// executed path.
	execPath      string
	runFromThread bool
	validate      func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string)
}

func TestTraceExecGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"simple_executable": {
			runnerConfig: &utils.RunnerConfig{},
			argv:         []string{"/bin/echo", "hello", "world"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[0].Args)
			},
		},
		"large_argument_list": {
			runnerConfig: &utils.RunnerConfig{},
			// The arguments are read from the new process' memory
			// (mm->arg_start .. mm->arg_end), so the whole argument list is
			// captured as long as it fits in the args buffer (bounded by bytes,
			// FULL_MAX_ARGS_ARR, rather than by a fixed number of arguments).
			argv: []string{"/bin/echo", "arg1", "arg2", "arg3", "arg4", "arg5", "arg6", "arg7", "arg8", "arg9", "arg10", "arg11", "arg12", "arg13", "arg14", "arg15", "arg16", "arg17", "arg18", "arg19", "arg20", "arg21"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[0].Args)
			},
		},
		"uid_gid": {
			runnerConfig: &utils.RunnerConfig{
				Uid:         1000,
				Gid:         1000,
				HostNetwork: false,
			},
			argv: []string{"/bin/ls", "-l", "/"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[0].Args)
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
		"mount_namespace_filter_blocked": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID+100)
			},
			argv: []string{"/bin/date"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				utils.ExpectNoEvent(t, info, "Expected 0 events", events)
			},
		},
		"error": {
			runnerConfig: &utils.RunnerConfig{},
			argv:         []string{"/bin/foobar", "hello"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[0].Args)
				require.Equal(t, "ENOENT", events[0].Error)
			},
		},
		"failed_exec_argv0_differs_from_path": {
			runnerConfig: &utils.RunnerConfig{},
			// execve() a non-existent path with an argv[0] that differs from it.
			// The reported args must reflect the real argv[0], not the path.
			execPath: "/bin/nonexistent-trace-exec-xyz",
			argv:     []string{"masked-name", "arg1"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[0].Args)
				require.Equal(t, "ENOENT", events[0].Error)
			},
		},
		"ctime": {
			runnerConfig: &utils.RunnerConfig{},
			argv:         []string{"/bin/echo", "ctime-test"},
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 1, "Expected 1 event but got %d", len(events))

				// Get the actual ctime of /bin/echo via stat
				expectedCtime := getCtimeNs(t, "/bin/echo")

				// ctime and fctime should both match /bin/echo's ctime
				// (for a non-script binary, exe and file are the same)
				require.Equal(t, expectedCtime, events[0].Ctime, "ctime should match stat ctime of /bin/echo")
				require.Equal(t, expectedCtime, events[0].Fctime, "fctime should match stat ctime of /bin/echo")

				// pctime: parent exe ctime should be non-zero
				require.NotZero(t, events[0].Pctime, "pctime should be non-zero")
			},
		},
		"successful_exec_from_thread": {
			runnerConfig:  &utils.RunnerConfig{},
			argv:          []string{"/bin/echo", "hello", "world"},
			runFromThread: true,
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 2, "Expected 2 events but got %d", len(events))
				// args are read from the new process' memory, so argv[0] is the
				// value passed to execve ("python3") and not the resolved path.
				require.Contains(t, events[0].Args, "python3"+traceexec.ArgsSeparator+"-c")
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[1].Args)
			},
		},
		"failed_exec_from_thread": {
			runnerConfig:  &utils.RunnerConfig{},
			argv:          []string{"/bin/meowmeow", "hello", "world"},
			runFromThread: true,
			validate: func(t *testing.T, info *utils.RunnerInfo, events []ExpectedTraceExecEvent, inputArgs []string) {
				require.Len(t, events, 2, "Expected 2 events but got %d", len(events))
				// args are read from the new process' memory, so argv[0] is the
				// value passed to execve ("python3") and not the resolved path.
				require.Contains(t, events[0].Args, "python3"+traceexec.ArgsSeparator+"-c")
				expectedArgs := strings.Join(inputArgs, traceexec.ArgsSeparator)
				require.Equal(t, expectedArgs, events[1].Args)
				require.Equal(t, "ENOENT", events[1].Error)
			},
		},
	}

	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap == nil {
				// by default we use the mount namespace of the runner
				mntnsFilterMap = utils.CreateMntNsFilterMap(t, runner.Info.MountNsID)
			} else {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					if testCase.runFromThread {
						generateEventFromThread(t, testCase.argv)
					} else {
						path := testCase.argv[0]
						if testCase.execPath != "" {
							path = testCase.execPath
						}
						p, err := os.StartProcess(path, testCase.argv, &os.ProcAttr{})
						if err == nil {
							defer p.Wait()
						}
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

// TestTraceExecTty checks the controlling terminal reported for a process that
// has one and for a process that has none. Both processes are started in their
// own session so that the controlling terminal does not depend on the one of
// the process running the test.
func TestTraceExecTty(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	// Open the pty outside of the runner: the file descriptors are inherited by
	// the child regardless of the namespaces it is started in.
	ptmx, pts, err := pty.Open()
	require.NoError(t, err, "Opening pty")
	defer ptmx.Close()
	defer pts.Close()

	var stat unix.Stat_t
	err = unix.Fstat(int(pts.Fd()), &stat)
	require.NoError(t, err, "Getting the device number of %s", pts.Name())
	expectedMajor := unix.Major(uint64(stat.Rdev))
	expectedMinor := unix.Minor(uint64(stat.Rdev))

	runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utils.RunWithRunner(t, runner, func() error {
			// First event: the pty is made the controlling terminal of the new
			// session, i.e. it is the controlling terminal of the process.
			argv := []string{"/bin/echo", "with-tty"}
			p, err := os.StartProcess(argv[0], argv, &os.ProcAttr{
				Files: []*os.File{pts, pts, pts},
				Sys: &syscall.SysProcAttr{
					Setsid:  true,
					Setctty: true,
					Ctty:    0,
				},
			})
			if err != nil {
				return err
			}
			if _, err := p.Wait(); err != nil {
				return err
			}

			// Second event: a new session without a controlling terminal.
			argv = []string{"/bin/echo", "without-tty"}
			p, err = os.StartProcess(argv[0], argv, &os.ProcAttr{
				Sys: &syscall.SysProcAttr{Setsid: true},
			})
			if err != nil {
				return err
			}
			_, err = p.Wait()
			return err
		})
		return nil
	}

	opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceExecEvent]{
		Image:          "trace_exec",
		Timeout:        5 * time.Second,
		MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
		OnGadgetRun:    onGadgetRun,
	}
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

	gadgetRunner.RunGadget()

	events := gadgetRunner.CapturedEvents
	require.Len(t, events, 2, "Expected 2 events but got %d", len(events))

	withTty := events[0]
	require.Contains(t, withTty.Args, "with-tty")
	require.Equal(t, expectedMajor, withTty.TtyMajor,
		"tty_major should be the major number of %s", pts.Name())
	require.Equal(t, expectedMinor, withTty.TtyMinor,
		"tty_minor should be the minor number of %s", pts.Name())

	withoutTty := events[1]
	require.Contains(t, withoutTty.Args, "without-tty")
	require.Zero(t, withoutTty.Tty, "tty should be 0 without a controlling terminal")
	require.Zero(t, withoutTty.TtyMajor, "tty_major should be 0 without a controlling terminal")
	require.Zero(t, withoutTty.TtyMinor, "tty_minor should be 0 without a controlling terminal")
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

func getCtimeNs(t *testing.T, path string) uint64 {
	t.Helper()
	var stat syscall.Stat_t
	err := syscall.Stat(path, &stat)
	require.NoError(t, err, "stat %s", path)
	return uint64(stat.Ctim.Sec)*1_000_000_000 + uint64(stat.Ctim.Nsec)
}
