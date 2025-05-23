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
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedBpfstatsEvent struct {
	GadgetID    string `json:"gadgetID"`
	GadgetImage string `json:"gadgetImage"`
	GadgetName  string `json:"gadgetName"`
	MapCount    int    `json:"mapCount"`
	MapMemory   int    `json:"mapMemory"`
	ProgID      int    `json:"progID"`
	ProgName    string `json:"progName"`
	ProgType    string `json:"progType"`
	Runcount    int    `json:"runcount"`
	Runtime     int    `json:"runtime"`
	Comms       string `json:"comms"`
	Pids        string `json:"pids"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	allPrograms    bool
	generateEvent  func(t *testing.T)
	expectedEvents []ExpectedBpfstatsEvent
}

const (
	testGadgetImage = "trace_open"
)

func TestBpfstatsGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	comm, err := os.Executable()
	require.NoError(t, err)
	comm = filepath.Base(comm)

	pids := fmt.Sprintf("%d", os.Getpid())

	testCases := map[string]testDef{
		"by_gadget": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			expectedEvents: []ExpectedBpfstatsEvent{
				{
					GadgetImage: gadgetrunner.GetGadgetImageName(testGadgetImage),
					ProgID:      0,
				},
			},
		},
		"by_programs": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			allPrograms:   true,
			expectedEvents: []ExpectedBpfstatsEvent{
				// programs from trace_open gadget. This introduces a dependency
				// on the trace_open gadget, but it's almost guranteed that this
				// gadget will have these two programs
				{
					GadgetImage: gadgetrunner.GetGadgetImageName(testGadgetImage),
					ProgName:    "ig_openat_e",
					ProgID:      utils.NormalizedInt,
					ProgType:    "TracePoint",
					Comms:       comm,
					Pids:        pids,
				},
				{
					GadgetImage: gadgetrunner.GetGadgetImageName(testGadgetImage),
					ProgName:    "ig_openat_x",
					ProgID:      utils.NormalizedInt,
					ProgType:    "TracePoint",
					Comms:       comm,
					Pids:        pids,
				},
				// TODO: test external program
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedBpfstatsEvent) {
				utils.NormalizeInt(&event.MapCount)
				utils.NormalizeInt(&event.MapMemory)
				utils.NormalizeInt(&event.ProgID)

				// Manually set the values to the normalized values because the
				// function doesn't modify the value when is 0
				event.Runcount = utils.NormalizedInt
				event.Runtime = utils.NormalizedInt
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					testCase.generateEvent(t)
					return nil
				})
				return nil
			}

			var paramValues map[string]string
			if testCase.allPrograms {
				paramValues = map[string]string{"operator.ebpf.all": "true"}
			}

			opts := gadgetrunner.GadgetRunnerOpts[ExpectedBpfstatsEvent]{
				Image:          "bpfstats",
				Timeout:        5 * time.Second,
				ParamValues:    paramValues,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
			gadgetRunner.RunGadget()

			for _, expectedEvent := range testCase.expectedEvents {
				expectedEvent.MapCount = utils.NormalizedInt
				expectedEvent.MapMemory = utils.NormalizedInt
				expectedEvent.Runcount = utils.NormalizedInt
				expectedEvent.Runtime = utils.NormalizedInt

				require.Contains(t, gadgetRunner.CapturedEvents, expectedEvent)
			}
		})
	}
}

func generateEvent(t *testing.T) {
	// Run a gadget so it's captured by the bpstats gadget
	opts := gadgetrunner.GadgetRunnerOpts[ExpectedBpfstatsEvent]{
		Image:   testGadgetImage,
		Timeout: 1 * time.Second,
	}
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.RunGadget()
}
