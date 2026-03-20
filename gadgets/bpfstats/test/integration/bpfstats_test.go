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
	"fmt"
	"testing"
	"time"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type bpfstatsEntry struct {
	GadgetID    string `json:"gadgetID"`
	GadgetName  string `json:"gadgetName"`
	GadgetImage string `json:"gadgetImage"`

	ProgID   uint32 `json:"progID"`
	ProgName string `json:"progName"`
	ProgType string `json:"progType"`

	Runtime  string `json:"runtime"`
	RunCount uint64 `json:"runcount"`

	MapMemory string `json:"mapMemory"`
	MapCount  uint64 `json:"mapCount"`

	CpuUsage         float64 `json:"cpuUsage"`
	CpuUsageRelative float64 `json:"cpuUsageRelative"`
	CpuTimeStr       string  `json:"cpuTimeStr"`

	Comms string `json:"comms"`
	Pids  string `json:"pids"`
}

func normalizeBpfstatsEntry(e *bpfstatsEntry) {
	e.GadgetID = ""
	e.ProgType = ""
	e.Comms = ""
	e.Pids = ""
	e.Runtime = ""
	e.RunCount = 0
	e.CpuUsage = 0
	e.CpuUsageRelative = 0
	e.CpuTimeStr = ""
}

func TestBpfstats_AllPrograms(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				"--timeout=5",
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags("--timeout=5"),
		)
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn("")))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &bpfstatsEntry{
					ProgID:   utils.NormalizedInt,
					MapCount: 0,
				}

				normalize := func(e *bpfstatsEntry) {
					normalizeBpfstatsEntry(e)
					utils.NormalizeInt(&e.ProgID)
					e.ProgName = ""
					e.MapMemory = ""
					e.MapCount = 0
					e.GadgetName = ""
					e.GadgetImage = ""
				}

				match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	bpfstatsCmd := igrunner.New("bpfstats", runnerOpts...)
	igtesting.RunTestSteps(
		[]igtesting.TestStep{utils.Sleep(2 * time.Second), bpfstatsCmd},
		t,
		testingOpts...,
	)
}

func TestBpfstats_GadgetsOnly(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				"--gadgets-only",
				"--timeout=5",
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				"--gadgets-only",
				"--timeout=5",
			),
		)
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn("")))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &bpfstatsEntry{
					GadgetImage: utils.NormalizedStr,
					MapCount:    utils.NormalizedInt,
				}

				normalize := func(e *bpfstatsEntry) {
					normalizeBpfstatsEntry(e)
					e.GadgetName = ""
					utils.NormalizeString(&e.GadgetImage)
					e.MapMemory = ""
					utils.NormalizeInt(&e.MapCount)
				}

				match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	bpfstatsCmd := igrunner.New("bpfstats", runnerOpts...)
	igtesting.RunTestSteps(
		[]igtesting.TestStep{utils.Sleep(2 * time.Second), bpfstatsCmd},
		t,
		testingOpts...,
	)
}
