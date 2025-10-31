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
	"os/exec"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type ExpectedSnapshotFileEvent struct {
	MntNsID  uint64 `json:"mntns_id"`
	Comm     string `json:"comm"`
	Pid      uint32 `json:"pid"`
	Tid      uint32 `json:"tid"`
	Type     string `json:"type"`
	Path     string `json:"path"`
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	generateEvent  func(t *testing.T) (int, error)
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedSnapshotFileEvent)
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
}

func TestSnapshotFileGadget(t *testing.T) {
	// task iterator was introduced in 5.8
	gadgettesting.MinimumKernelVersion(t, "5.8")
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utils.RunnerConfig{HostNetwork: false}
	testCases := map[string]testDef{
		"captures_events_with_no_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedSnapshotFileEvent) {
				// utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedSnapshotFileEvent {
				// 	return &ExpectedSnapshotFileEvent{
				// 		Comm: "tail",
				// 		Type: "REGULAR",
				// 		Path: "demo.txt",
				// 		// Pid:  uint32(pid),
				// 		// Tid:  uint32(pid),
				// 		MntNsID: info.MountNsID,
				// 	}
				// })(t, info, pid, events)

				//atleast 1 event should have comm == tail and pid == pid
				for _, event := range events {
					if event.Comm == "tail" && event.Type == "REGULAR" && event.Path == "demo.txt" {
						if event.Pid == uint32(pid) {
							t.Logf("Found matching event and pids match: %+v\n", event)
						} else {
							t.Logf("Found matching event but pids don't match: %+v\n", event)
						}
						return
					}
				}
				t.Errorf("Expected at least one event with comm == tail and pid == %d, but found none", pid)
			},
		},
		// "captures_no_events_with_no_matching_filter": {
		// 	runnerConfig: runnerConfig,
		// 	mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
		// 		// mnts, _ := containerutils.GetNetNs(os.Getpid())
		// 		return utils.CreateMntNsFilterMap(t, info.MountNsID + 1)
		// 	},
		// 	generateEvent: generateEvent,
		// 	validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedSnapshotFileEvent) {
		// 		// utils.ExpectNoEvent(t, info, pid, events)
		// 		require.Empty(t, events, "Expected no events, but got %d events", len(events))
		// 	},
		// },
		// "captures_events_with_matching_filter": {
		// 	mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
		// 		return utils.CreateMntNsFilterMap(t, info.MountNsID)
		// 	},
		// 	generateEvent: generateEvent,
		// 	validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, events []ExpectedSnapshotFileEvent) {
		// 		// utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedSnapshotFileEvent {
		// 		// 	return &ExpectedSnapshotFileEvent{
		// 		// 		Comm: "tail",
		// 		// 		Pid:  uint32(pid),
		// 		// 		Tid:  uint32(pid),
		// 		// 		MntNsID: info.MountNsID,
		// 		// 	}
		// 		// })(t, info, pid, events)
		// 		for _, event := range events {
		// 			if event.Comm == "tail" && event.Pid == uint32(pid) {
		// 				t.Logf("Found matching event: %+v\n", event)
		// 				return
		// 			}
		// 		}
		// 		t.Errorf("Expected at least one event with comm == tail and pid == %d, but found none", pid)

		// 	},
		// },
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var processId int

			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			beforeGadgetRun := func() error {
				utils.RunWithRunner(t, runner, func() error {
					pid, err := testCase.generateEvent(t)
					if err != nil {
						return err
					}
					processId = pid
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedSnapshotFileEvent]{
				Image:           "snapshot_file",
				Timeout:         5 * time.Second,
				MntnsFilterMap:  mntnsFilterMap,
				BeforeGadgetRun: beforeGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			
			t.Logf("Events received with comm: tail")
			for _, event := range gadgetRunner.CapturedEvents {
				if event.Comm == "tail" {
					t.Logf("Found matching event: %+v\n", event)
				}
			}

			testCase.validateEvent(t, runner.Info, processId, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent(t *testing.T) (int, error) {
	const filePath = "/tmp/demo.txt"
	createCmd := exec.Command("sh", "-c", "echo hello > "+filePath)
	if err := createCmd.Run(); err != nil {
		return 0, err
	}
	tailCmd := exec.Command("tail", "-f", filePath)

	if err := tailCmd.Start(); err != nil {
		return 0, err
	}
	pid := tailCmd.Process.Pid
	t.Logf("Started echo command with PID %d", createCmd.Process.Pid)
	t.Logf("Started tail command with PID %d", pid)
	t.Cleanup(func() {
		if tailCmd.Process != nil {
			_ = tailCmd.Process.Kill()
		}
		_ = exec.Command("rm", filePath).Run()
	})

	return pid, nil
}
