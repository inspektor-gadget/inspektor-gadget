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
	"errors"
	"fmt"
	"os"
	"path"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type Process struct {
	PPid  uint32 `json:"ppid"`
	Pid   uint32 `json:"pid"`
	Tid   uint32 `json:"tid"`
	Comm  string `json:"comm"`
	PComm string `json:"pcomm"`
}

type EventDetails struct {
	FileName string
	Ino      uint32
	InoDir   uint32
}

type ExpectedFsnotifyEvent struct {
	Timestamp string `json:"timestamp"`

	Type string `json:"type"`

	TraceeProc Process `json:"tracee_proc"`
	TracerProc Process `json:"tracer_proc"`

	TraceeMntnsId uint64 `json:"tracee_mntns_id"`
	TracerMntnsId uint64 `json:"tracer_mntns_id"`

	TraceeUId uint32 `json:"tracee_uid"`
	TraceeGId uint32 `json:"tracee_gid"`
	TracerUId uint32 `json:"tracer_uid"`
	TracerGId uint32 `json:"tracer_gid"`

	Prio uint32 `json:"prio"`

	FaMask string `json:"fa_mask"`
	IMask  string `json:"i_mask"`

	FaType     string `json:"fa_type"`
	FaPId      uint32 `json:"fa_pid"`
	FaFlags    uint32 `json:"fa_flags"`
	FaFFlags   uint32 `json:"fa_f_flags"`
	FaResponse string `json:"fa_response"`

	IWd     int32  `json:"i_wd"`
	ICookie uint32 `json:"i_cookie"`
	IIno    uint32 `json:"i_ino"`
	IInoDir uint32 `json:"i_ino_dir"`

	Name string `json:"name"`
}

type testDef struct {
	runnerConfig  *utils.RunnerConfig
	generateEvent func() (EventDetails, error)
	validateEvent func(t *testing.T, info *utils.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent)
}

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.MinimumKernelVersion(t, "5.4")
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utils.RunnerConfig{}

	// i_ino field is not available in Linux < 5.11
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/4222
	ignoreInvalidIno := false
	if gadgettesting.CheckMinimumKernelVersion(t, "5.11") {
		ignoreInvalidIno = true
		t.Logf("Linux < 5.11 (%s) does not give the inode number. This field will not be tested.", gadgettesting.GetKernelVersion(t))
	}

	testCases := map[string]testDef{
		"captures_inotify_event": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utils.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent) {
				utils.ExpectAtLeastOneEvent(func(info *utils.RunnerInfo, pid int) *ExpectedFsnotifyEvent {
					ev := &ExpectedFsnotifyEvent{
						Timestamp: utils.NormalizedStr,

						Type:  "inotify",
						IMask: "IN_MODIFY",

						TraceeMntnsId: info.MountNsID,
						TracerMntnsId: utils.NormalizedInt,

						FaType:     utils.NormalizedStr,
						FaResponse: utils.NormalizedStr,

						IWd:     utils.NormalizedInt,
						IIno:    eventDetails.Ino,
						IInoDir: eventDetails.InoDir,

						Name: eventDetails.FileName,
					}
					if ignoreInvalidIno {
						ev.IIno = utils.NormalizedInt
					}
					return ev
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var eventDetails EventDetails
			runner := utils.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedFsnotifyEvent) {
				utils.NormalizeString(&event.Timestamp)
				utils.NormalizeInt(&event.TracerMntnsId)

				utils.NormalizeString(&event.FaType)
				utils.NormalizeString(&event.FaResponse)
				if ignoreInvalidIno {
					event.IIno = utils.NormalizedInt
				}
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utils.RunWithRunner(t, runner, func() error {
					var err error
					eventDetails, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedFsnotifyEvent]{
				Image:          "fsnotify",
				Timeout:        5 * time.Second,
				OnGadgetRun:    onGadgetRun,
				NormalizeEvent: normalizeEvent,
			}

			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, eventDetails, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (EventDetails, error) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return EventDetails{}, err
	}
	defer watcher.Close()

	err = watcher.Add(os.TempDir())
	if err != nil {
		return EventDetails{}, err
	}

	// event 1
	newFile, err := os.CreateTemp(os.TempDir(), "test-*.txt")
	if err != nil {
		return EventDetails{}, err
	}
	defer newFile.Close()

	// event 2
	_, err = newFile.WriteString("Hello, fsnotify!")
	if err != nil {
		return EventDetails{}, err
	}

	// Receiving events.
forLoop:
	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return EventDetails{}, errors.New("channel closed")
			}
			if event.Has(fsnotify.Write) {
				if event.Name != newFile.Name() {
					return EventDetails{}, fmt.Errorf("watcher: unexpected event: %q, expected %q", event.Name, newFile.Name())
				}
				break forLoop
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return EventDetails{}, errors.New("channel closed")
			}
			return EventDetails{}, fmt.Errorf("watcher: %w", err)
		}
	}

	// Get inode values of test file and its parent directory
	fileInode, err := utils.GetInode(newFile.Name())
	if err != nil {
		return EventDetails{}, err
	}
	dirInode, err := utils.GetInode(path.Dir(newFile.Name()))
	if err != nil {
		return EventDetails{}, err
	}

	fileName := path.Base(newFile.Name())
	eventDetails := EventDetails{
		FileName: fileName,
		Ino:      uint32(fileInode),
		InoDir:   uint32(dirInode),
	}
	return eventDetails, nil
}
