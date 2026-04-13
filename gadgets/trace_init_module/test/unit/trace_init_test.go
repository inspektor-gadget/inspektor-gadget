// Copyright 2026 The Inspektor Gadget authors
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
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceInitModuleEvent struct {
	Proc utils.Process `json:"proc"`

	Syscall     string `json:"syscall"`
	Len         uint64 `json:"len"`
	Fd          int32  `json:"fd"`
	Filepath    string `json:"filepath"`
	Flags       uint32 `json:"flags"`
	ParamValues string `json:"param_values"`
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
	generateEvent  func(lenBytes uint64, params string) error
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, expectedLen uint64, expectedParams string, events []ExpectedTraceInitModuleEvent)
}

func TestTraceInitModuleGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)

	cases := map[string]testDef{
		"init_module_captures_all_events": {
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, expectedLen uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, _ uint64) *ExpectedTraceInitModuleEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceInitModuleEvent{
						Proc:        proc,
						Syscall:     "init_module",
						Len:         expectedLen,
						ParamValues: expectedParams,
					}
				})(t, info, expectedLen, events)
			},
		},
		"init_module_no_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ uint64, _ string, events []ExpectedTraceInitModuleEvent) {
				utils.ExpectNoEvent(t, info, uint64(0), events)
			},
		},
		"init_module_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, expectedLen uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				require.NotEmpty(t, events)
				require.Equal(t, "init_module", events[0].Syscall)
				require.Equal(t, expectedLen, events[0].Len)
				require.Equal(t, expectedParams, events[0].ParamValues)
			},
		},
		"finit_module_captures_all_events": {
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateFinitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				// Just check if we got any finit_module events
				found := false
				for _, event := range events {
					if event.Syscall == "finit_module" {
						found = true
						t.Logf("Found finit_module event: fd=%d, filepath=%s, params=%s",
							event.Fd, event.Filepath, event.ParamValues)
						break
					}
				}
				require.True(t, found, "Expected at least one finit_module event")
			},
		},
		"finit_module_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateFinitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				require.NotEmpty(t, events)
				require.Equal(t, "finit_module", events[0].Syscall)
				require.Equal(t, expectedParams, events[0].ParamValues)
				require.GreaterOrEqual(t, events[0].Fd, int32(0))
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utils.NewRunnerWithTest(t, tc.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if tc.mntnsFilterMap != nil {
				mntnsFilterMap = tc.mntnsFilterMap(runner.Info)
			}

			expectedLen := uint64(32)
			expectedParams := "foo=bar"

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					return tc.generateEvent(expectedLen, expectedParams)
				})
				return nil
			}

			normalizeEvent := func(event *ExpectedTraceInitModuleEvent) {
				utils.NormalizeParentTid(&event.Proc)
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceInitModuleEvent]{
				Image:          "trace_init_module",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			tc.validateEvent(t, runner.Info, expectedLen, expectedParams, gadgetRunner.CapturedEvents)
		})
	}
}

func generateInitModuleEvent(lenBytes uint64, params string) error {
	buf := make([]byte, lenBytes)
	for i := range buf {
		buf[i] = 0xaa
	}

	paramPtr, err := syscall.BytePtrFromString(params)
	if err != nil {
		return err
	}

	_, _, errno := syscall.Syscall(syscall.SYS_INIT_MODULE,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(paramPtr)),
	)
	_ = errno
	return nil
}

func generateFinitModuleEvent(_ uint64, params string) error {
	// Create a temporary file with dummy module content
	tmpFile, err := os.CreateTemp("", "dummy-module-*.ko")
	if err != nil {
		return err
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	// Write some dummy data
	_, err = tmpFile.Write([]byte{0x7f, 0x45, 0x4c, 0x46}) // ELF magic
	if err != nil {
		return err
	}

	paramPtr, err := syscall.BytePtrFromString(params)
	if err != nil {
		return err
	}

	// Call finit_module syscall
	_, _, errno := syscall.Syscall(unix.SYS_FINIT_MODULE,
		tmpFile.Fd(),
		uintptr(unsafe.Pointer(paramPtr)),
		0, // flags
	)
	_ = errno
	return nil
}
