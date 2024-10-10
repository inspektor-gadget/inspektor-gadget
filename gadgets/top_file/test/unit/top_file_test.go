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

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTopFileEvent struct {
	Comm    string `json:"comm"`
	Dev     uint32 `json:"dev"`
	File    string `json:"file"`
	Gid     uint32 `json:"gid"`
	MntnsID uint64 `json:"mntns_id"`
	Pid     int    `json:"pid"`
	Tid     int    `json:"tid"`
	Uid     uint32 `json:"uid"`
	RBytes  uint64 `json:"rbytes"`
	Reads   uint64 `json:"reads"`
	WBytes  uint64 `json:"wbytes"`
	Writes  uint64 `json:"writes"`
	T       string `json:"t"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	generateEvent  func() (string, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedTopFileEvent)
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
}

func TestTopFileGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_events_with_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, filepath string, events []ExpectedTopFileEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedTopFileEvent {
					return &ExpectedTopFileEvent{
						Comm: info.Comm,
						T:    "R",
						File: filepath,

						Pid: info.Pid,
						Tid: info.Tid,

						// Only check the existence.
						Writes: utils.NormalizedInt,

						MntnsID: info.MountNsID,
						Uid:     0,
						Gid:     0,
						Dev:     0,

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
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
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
				utilstest.RunWithRunner(t, runner, func() error {
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
