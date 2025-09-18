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
	"os/exec"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceCapabilitiesEvent struct {
	Proc          utils.Process
	Cap           string `json:"cap"`
	Audit         uint32 `json:"audit"`
	Syscall       string `json:"syscall"`
	CurrentUserNs uint64 `json:"current_userns"`
	TargetUserNs  uint64 `json:"target_userns"`
	Insetid       uint32 `json:"insetid"`
}

type testDef struct {
	name                string
	generateEvent       func()
	requestedPermission string
	syscall             string
	insetId             uint32
}

func TestTraceCapabilitiesGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := []testDef{
		{
			name: "raw_socket",
			generateEvent: func() {
				fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_ICMP)
				if err != nil {
					syscall.Close(fd)
				}
			},
			syscall:             "SYS_SOCKET",
			requestedPermission: "CAP_NET_RAW",
		},
		{
			name: "device_access",
			generateEvent: func() {
				fd, _ := syscall.Open("/dev/mem", syscall.O_RDONLY, 0)
				if fd >= 0 {
					syscall.Close(fd)
				}
			},
			requestedPermission: "CAP_SYS_RAWIO",
			syscall:             "SYS_OPENAT",
		},
		{
			name: "perf_event_open",
			generateEvent: func() {
				// Open perf event with dummy args; usually fails unless properly configured.
				attr := &unix.PerfEventAttr{Type: unix.PERF_TYPE_HARDWARE, Size: uint32(unsafe.Sizeof(unix.PerfEventAttr{}))}
				fd, _ := unix.PerfEventOpen(attr, -1, 0, -1, 0)
				if fd >= 0 {
					syscall.Close(fd)
				}
			},
			requestedPermission: func() string {
				kernelVersion := gadgettesting.GetKernelVersion(t)
				if kernelVersion.Kernel < 5 || (kernelVersion.Kernel == 5 && kernelVersion.Major < 8) {
					// CAP_SYS_ADMIN is requested for kernel < 5.8
					return "CAP_SYS_ADMIN"
				}
				return "CAP_PERFMON"
			}(),
			syscall: "SYS_PERF_EVENT_OPEN",
		},
		{
			name: "nice",
			generateEvent: func() {
				currPriority, _ := syscall.Getpriority(syscall.PRIO_PROCESS, 0)
				err := syscall.Setpriority(syscall.PRIO_PROCESS, 0, -1)
				if err != nil {
					syscall.Setpriority(syscall.PRIO_PROCESS, 0, currPriority)
				}
			},
			requestedPermission: "CAP_SYS_NICE",
			syscall:             "SYS_SETPRIORITY",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					testCase.generateEvent()
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceCapabilitiesEvent]{
				Image:          "trace_capabilities",
				Timeout:        5 * time.Second,
				MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, fd int) *ExpectedTraceCapabilitiesEvent {
				return &ExpectedTraceCapabilitiesEvent{
					Proc:          info.Proc,
					Cap:           testCase.requestedPermission,
					Audit:         1,
					Insetid:       testCase.insetId,
					CurrentUserNs: info.UserNsID,
					TargetUserNs:  info.UserNsID,
					Syscall:       testCase.syscall,
				}
			})(t, runner.Info, 0, gadgetRunner.CapturedEvents)
		})
	}
}

func TestNonAuditCapabilities(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runner := utils.NewRunnerWithTest(t, &utils.RunnerConfig{})
	var cmd *exec.Cmd
	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utils.RunWithRunner(t, runner, func() error {
			cmd = exec.Command("/bin/cat", "/proc/kallsyms")
			err := cmd.Run()
			require.NoError(t, err)
			return nil
		})
		return nil
	}
	opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceCapabilitiesEvent]{
		Image:          "trace_capabilities",
		Timeout:        5 * time.Second,
		MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
		OnGadgetRun:    onGadgetRun,
	}
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

	gadgetRunner.RunGadget()

	utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, fd int) *ExpectedTraceCapabilitiesEvent {
		return &ExpectedTraceCapabilitiesEvent{
			Proc: utils.Process{
				Pid:     uint32(cmd.Process.Pid),
				Tid:     uint32(cmd.Process.Pid),
				Comm:    "cat",
				MntNsID: info.MountNsID,
				Parent: utils.Parent{
					Comm: "unit.test",
					Pid:  uint32(os.Getpid()),
				},
			},
			Cap:           "CAP_SYSLOG",
			Audit:         0,
			Insetid:       0,
			CurrentUserNs: info.UserNsID,
			TargetUserNs:  info.UserNsID,
			Syscall:       "SYS_OPENAT",
		}
	})(t, runner.Info, 0, gadgetRunner.CapturedEvents)
}
