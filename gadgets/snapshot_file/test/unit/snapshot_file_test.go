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
	"path/filepath"
	"testing"
	"time"

	"github.com/cilium/ebpf"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedSnapshotFileEvent struct {
	MntNsID uint64 `json:"mntns_id"`
	Comm    string `json:"comm"`
	Pid     uint32 `json:"pid"`
	Tid     uint32 `json:"tid"`
	Type    string `json:"type"`
	Path    string `json:"path"`
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	generateEvent  func(t *testing.T) (string, int, error)
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, pid int, filePath string, events []ExpectedSnapshotFileEvent)
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
}

func TestSnapshotFileGadget(t *testing.T) {
	// task iterator was introduced in 5.8
	gadgettesting.MinimumKernelVersion(t, "5.8")
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utils.RunnerConfig{HostNetwork: true}
	testCases := map[string]testDef{
		"captures_events_with_no_filter": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, filePath string, events []ExpectedSnapshotFileEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedSnapshotFileEvent {
					return &ExpectedSnapshotFileEvent{
						Comm:    "tail",
						Type:    "REGULAR",
						Path:    filePath,
						Pid:     uint32(pid),
						Tid:     uint32(pid),
						MntNsID: info.MountNsID,
					}
				})(t, info, pid, events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: runnerConfig,
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, filePath string, events []ExpectedSnapshotFileEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedSnapshotFileEvent {
					return &ExpectedSnapshotFileEvent{
						Comm:    "tail",
						Type:    "REGULAR",
						Path:    filePath,
						Pid:     uint32(pid),
						Tid:     uint32(pid),
						MntNsID: info.MountNsID,
					}
				})(t, info, pid, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: runnerConfig,
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				mnts, _ := containerutils.GetNetNs(os.Getpid())
				return utils.CreateMntNsFilterMap(t, mnts)
			},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, pid int, filePath string, events []ExpectedSnapshotFileEvent) {
				for _, event := range events {
					if event.Comm == "tail" && event.Type == "REGULAR" && event.Path == filePath && event.Pid == uint32(pid) {
						t.Errorf("Did not expect any matching event, but found one: %+v", event)
					}
				}
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var processId int
			var filePath string

			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			beforeGadgetRun := func() error {
				utils.RunWithRunner(t, runner, func() error {
					uniqueFilePath, pid, err := testCase.generateEvent(t)
					if err != nil {
						return err
					}
					processId = pid
					filePath = uniqueFilePath
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedSnapshotFileEvent]{
				Image:           "snapshot_file",
				Timeout:         5 * time.Second,
				MntnsFilterMap:  mntnsFilterMap,
				BeforeGadgetRun: beforeGadgetRun,
				ParamValues: api.ParamValues{
					"operator.oci.ebpf.paths": "true", // unique full paths ensure non interference between parallel tests
				},
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()
			testCase.validateEvent(t, runner.Info, processId, filePath, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent(t *testing.T) (string, int, error) {
	tempDir := t.TempDir()
	filePath := filepath.Join(tempDir, "demo.txt")

	createCmd := exec.Command("sh", "-c", "echo hello > "+filePath)
	if err := createCmd.Run(); err != nil {
		return "", 0, err
	}

	tailCmd := exec.Command("tail", "-f", filePath)
	if err := tailCmd.Start(); err != nil {
		return "", 0, err
	}

	pid := tailCmd.Process.Pid

	t.Cleanup(func() {
		if tailCmd.Process != nil {
			_ = tailCmd.Process.Kill()
		}
	})
	return filePath, pid, nil
}
