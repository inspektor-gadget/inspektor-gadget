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
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceInitModuleEvent struct {
	Proc utils.Process `json:"proc"`

	Len         uint64 `json:"len"`
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
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, expectedLen uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, _ uint64) *ExpectedTraceInitModuleEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceInitModuleEvent{
						Proc:        proc,
						Len:         expectedLen,
						ParamValues: expectedParams,
					}
				})(t, info, expectedLen, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ uint64, _ string, events []ExpectedTraceInitModuleEvent) {
				utils.ExpectNoEvent(t, info, uint64(0), events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateInitModuleEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, expectedLen uint64, expectedParams string, events []ExpectedTraceInitModuleEvent) {
				require.NotEmpty(t, events)
				require.Equal(t, expectedLen, events[0].Len)
				require.Equal(t, expectedParams, events[0].ParamValues)
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
