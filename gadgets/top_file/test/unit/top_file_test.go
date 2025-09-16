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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTopFileEvent struct {
	Proc   utils.Process `json:"proc"`
	Dev    uint32        `json:"dev"`
	File   string        `json:"file"`
	RBytes uint64        `json:"rbytes_raw"`
	Reads  uint64        `json:"reads"`
	WBytes uint64        `json:"wbytes_raw"`
	Writes uint64        `json:"writes"`
	T      string        `json:"t"`
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	generateEvent  func() (string, error)
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, filepath string, events []ExpectedTopFileEvent)
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
}

func TestTopFileGadget(t *testing.T) {
	// BPF_MAP_LOOKUP_AND_DELETE_BATCH used by the ebpf operator was introduced
	// in
	// https://github.com/torvalds/linux/commit/057996380a42bb64ccc04383cfa9c0ace4ea11f0
	gadgettesting.MinimumKernelVersion(t, "5.6")
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utils.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_events_with_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, filepath string, events []ExpectedTopFileEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedTopFileEvent {
					return &ExpectedTopFileEvent{
						Proc: info.Proc,
						T:    "R",
						File: filepath,

						// Only check the existence.
						Writes: utils.NormalizedInt,
						Dev:    0,

						// Nothing is being read from the file.
						Reads:  0,
						RBytes: 0,
						WBytes: 10240,
					}
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var filepath string
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			params := map[string]string{
				"operator.oci.ebpf.map-fetch-interval": "1000ms",
			}

			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			normalizeEvent := func(event *ExpectedTopFileEvent) {
				utils.NormalizeInt(&event.Writes)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					var err error
					filepath, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTopFileEvent]{
				Image:          "top_file",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				ParamValues:    params,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, filepath, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (string, error) {
	temp, err := os.MkdirTemp("", "test")
	if err != nil {
		return "", err
	}
	filepath := filepath.Join(temp, "foo")
	file, err := os.Create(filepath)
	if err != nil {
		return "", err
	}

	buf := make([]byte, 10240)
	_, err = file.Write(buf)
	if err != nil {
		return "", err
	}
	return filepath, nil
}
