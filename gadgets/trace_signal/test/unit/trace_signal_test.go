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
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type traceSignalEvent struct {
	Proc      utils.Process `json:"proc"`
	Signal    string        `json:"sig"`
	SignalRaw int           `json:"sig_raw"`
	Error     string        `json:"error"`
}

type testDef struct {
	name   string
	signal syscall.Signal
}

func TestTraceSignalGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := []testDef{
		{
			name:   "kill",
			signal: syscall.SIGKILL,
		},
		{
			name:   "sigterm",
			signal: syscall.SIGTERM,
		},
		{
			name:   "sigint",
			signal: syscall.SIGINT,
		},
		{
			name:   "sigusr1",
			signal: syscall.SIGUSR1,
		},
		{
			name:   "sigusr2",
			signal: syscall.SIGUSR2,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			t.Parallel()
			runner := utils.NewRunnerWithTest(t, nil)

			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					p, err := os.StartProcess("/usr/bin/sleep", []string{"/usr/bin/sleep", "2"}, &os.ProcAttr{})
					require.NoError(t, err, "start process")
					defer p.Wait()
					err = p.Signal(testCase.signal)
					require.NoError(t, err, "signal process")
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[traceSignalEvent]{
				Image:          "trace_signal",
				Timeout:        5 * time.Second,
				ParamValues:    api.ParamValues{},
				OnGadgetRun:    onGadgetRun,
				MntnsFilterMap: utils.CreateMntNsFilterMap(t, runner.Info.MountNsID),
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			utils.ExpectOneEvent(func(info *utils.RunnerInfo, fd int) *traceSignalEvent {
				return &traceSignalEvent{
					Proc:      info.Proc,
					Signal:    signalName(testCase.signal),
					SignalRaw: int(testCase.signal),
					Error:     "",
				}
			})(t, runner.Info, 0, gadgetRunner.CapturedEvents)
		})
	}
}

func signalName(sig syscall.Signal) string {
	switch sig {
	case syscall.SIGKILL:
		return "SIGKILL"
	case syscall.SIGTERM:
		return "SIGTERM"
	case syscall.SIGINT:
		return "SIGINT"
	case syscall.SIGUSR1:
		return "SIGUSR1"
	case syscall.SIGUSR2:
		return "SIGUSR2"
	default:
		return sig.String() // fallback to default
	}
}
