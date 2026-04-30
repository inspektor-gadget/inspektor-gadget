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
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type ExpectedTraceLinkEvent struct {
	Proc     utils.Process `json:"proc"`
	IsSym    bool          `json:"is_symlink"`
	Target   string        `json:"target"`
	LinkPath string        `json:"linkpath"`
}

type generatedPaths struct {
	target   string
	linkPath string
}

type testDef struct {
	runnerConfig   *utils.RunnerConfig
	mntnsFilterMap func(info *utils.RunnerInfo) *ebpf.Map
	generateEvent  func(t *testing.T) (generatedPaths, error)
	validateEvent  func(t *testing.T, info *utils.RunnerInfo, fd int, paths generatedPaths, events []ExpectedTraceLinkEvent)
}

func TestTraceLinkGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"captures_all_events_with_no_filters_configured": {
			runnerConfig:  &utils.RunnerConfig{},
			generateEvent: generateHardlinkEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, paths generatedPaths, events []ExpectedTraceLinkEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, fd int) *ExpectedTraceLinkEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceLinkEvent{
						Proc:     proc,
						IsSym:    false,
						Target:   paths.target,
						LinkPath: paths.linkPath,
					}
				})(t, info, fd, events)
			},
		},
		"captures_no_events_with_no_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, 0)
			},
			generateEvent: generateHardlinkEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, paths generatedPaths, events []ExpectedTraceLinkEvent) {
				utils.ExpectNoEvent(t, info, fd, events)
			},
		},
		"captures_events_with_matching_filter": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateHardlinkEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, paths generatedPaths, events []ExpectedTraceLinkEvent) {
				utils.ExpectOneEvent(func(info *utils.RunnerInfo, fd int) *ExpectedTraceLinkEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceLinkEvent{
						Proc:     proc,
						IsSym:    false,
						Target:   paths.target,
						LinkPath: paths.linkPath,
					}
				})(t, info, fd, events)
			},
		},
		"captures_symlink_event": {
			runnerConfig: &utils.RunnerConfig{},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateSymlinkEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, fd int, paths generatedPaths, events []ExpectedTraceLinkEvent) {
				utils.ExpectOneEvent(func(info *utils.RunnerInfo, fd int) *ExpectedTraceLinkEvent {
					proc := info.Proc
					utils.NormalizeParentTid(&proc)
					return &ExpectedTraceLinkEvent{
						Proc:     proc,
						IsSym:    true,
						Target:   paths.target,
						LinkPath: paths.linkPath,
					}
				})(t, info, fd, events)
			},
		},
		"event_has_UID_and_GID_of_user_generating_event": {
			runnerConfig: &utils.RunnerConfig{
				Uid: int(1435),
				Gid: int(6789),
			},
			mntnsFilterMap: func(info *utils.RunnerInfo) *ebpf.Map {
				return utils.CreateMntNsFilterMap(t, info.MountNsID)
			},
			generateEvent: generateHardlinkEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, _ int, _ generatedPaths, events []ExpectedTraceLinkEvent) {
				require.Len(t, events, 1, "expected one event")
				require.Equal(t, uint32(info.Uid), events[0].Proc.Creds.Uid)
				require.Equal(t, uint32(info.Gid), events[0].Proc.Creds.Gid)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var generated generatedPaths
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					var err error
					generated, err = testCase.generateEvent(t)
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			normalizeEvent := func(event *ExpectedTraceLinkEvent) {
				utils.NormalizeParentTid(&event.Proc)
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedTraceLinkEvent]{
				Image:          "trace_link",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, 0, generated, gadgetRunner.CapturedEvents)
		})
	}
}

// generateHardlinkEvent creates a hard link and cleans up afterwards.
func generateHardlinkEvent(t *testing.T) (generatedPaths, error) {
	base := t.TempDir()
	oldpath := base + "/trace_link_test_old"
	newpath := base + "/trace_link_test_new"

	// Create the source file
	f, err := os.Create(oldpath)
	if err != nil {
		return generatedPaths{}, err
	}
	f.Close()

	// Create the hard link
	err = unix.Link(oldpath, newpath)
	if err != nil {
		os.Remove(oldpath)
		return generatedPaths{}, err
	}

	return generatedPaths{target: oldpath, linkPath: newpath}, nil
}

// generateSymlinkEvent creates a symlink and cleans up afterwards.
func generateSymlinkEvent(t *testing.T) (generatedPaths, error) {
	base := t.TempDir()
	newpath := base + "/trace_link_test_symlink"
	target := "../trace_link_symlink_target"

	err := unix.Symlink(target, newpath)
	if err != nil {
		return generatedPaths{}, err
	}

	return generatedPaths{target: target, linkPath: newpath}, nil
}
