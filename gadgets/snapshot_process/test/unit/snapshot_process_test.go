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
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type ExpectedSnapshotProcessEvent struct {
	Comm      string `json:"comm"`
	Pid       int    `json:"pid"`
	Tid       int    `json:"tid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	ParentPid int    `json:"ppid"`
	MountNsID uint64 `json:"mntns_id"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	generateEvent  func() (int, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []ExpectedSnapshotProcessEvent)
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
}

func TestSnapshotProcessGadget(t *testing.T) {
	utilstest.RequireRoot(t)
	runnerConfig := &utilstest.RunnerConfig{}
	testCases := map[string]testDef{
		"captures_events_with_no_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []ExpectedSnapshotProcessEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *ExpectedSnapshotProcessEvent {
					return &ExpectedSnapshotProcessEvent{
						Comm:      "sleep",
						Pid:       sleepPid,
						Tid:       sleepPid,
						Uid:       0,
						Gid:       0,
						ParentPid: info.Tid,
						MountNsID: info.MountNsID,
					}
				})(t, info, sleepPid, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: runnerConfig,
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				mnts, _ := containerutils.GetNetNs(os.Getpid())
				return utilstest.CreateMntNsFilterMap(t, mnts)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []ExpectedSnapshotProcessEvent) {
				utilstest.ExpectNoEvent(t, info, sleepPid, events)
			},
		},
		"captures_events_with_matching_filter": {
			mntnsFilterMap: func(info *utilstest.RunnerInfo) *ebpf.Map {
				return utilstest.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []ExpectedSnapshotProcessEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, sleepPid int) *ExpectedSnapshotProcessEvent {
					return &ExpectedSnapshotProcessEvent{
						Comm:      "sleep",
						Pid:       sleepPid,
						Tid:       sleepPid,
						Uid:       0,
						Gid:       0,
						ParentPid: info.Tid,
						MountNsID: info.MountNsID,
					}
				})(t, info, sleepPid, events)
			},
		},
		"no_threads_are_captured": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, sleepPid int, events []ExpectedSnapshotProcessEvent) {
				if len(events) == 0 {
					t.Fatalf("no events were captured")
				}
				for _, event := range events {
					require.Equal(t, event.Pid, event.Tid)
				}
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var processId int

			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			beforeGadgetRun := func() error {
				// Use the runner to generate an event
				utilstest.RunWithRunner(t, runner, func() error {
					pid, err := testCase.generateEvent()
					if err != nil {
						return err
					}
					processId = pid
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedSnapshotProcessEvent]{
				Image:           "snapshot_process",
				Timeout:         5 * time.Second,
				MntnsFilterMap:  mntnsFilterMap,
				BeforeGadgetRun: beforeGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, processId, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (int, error) {
	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		return 0, err
	}

	return cmd.Process.Pid, nil
}
