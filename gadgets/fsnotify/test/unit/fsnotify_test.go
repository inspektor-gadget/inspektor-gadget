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
	"fmt"
	"os"
	"path"
	"syscall"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

const TASK_COMM_LEN = 16

type Process struct {
	PPid  uint32    `json:"ppid"`
	Pid   uint32    `json:"pid"`
	Tid   uint32    `json:"tid"`
	Comm  [TASK_COMM_LEN]byte `json:"comm"`
	PComm [TASK_COMM_LEN]byte `json:"pcomm"`
};

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

	FaMask uint32 `json:"fa_mask"`
	IMask  uint32 `json:"i_mask"`

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
	runnerConfig  *utilstest.RunnerConfig
	generateEvent func() (EventDetails, error)
	validateEvent func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent)
}

func TestFsnotifyGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	runnerConfig := &utilstest.RunnerConfig{}

	testCases := map[string]testDef{
		"captures_inotify_event": {
			runnerConfig:  runnerConfig,
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, eventDetails EventDetails, events []ExpectedFsnotifyEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, pid int) *ExpectedFsnotifyEvent {
					return &ExpectedFsnotifyEvent{
						Timestamp: utils.NormalizedStr,

						Type:  "inotify",
						IMask: 0x08000002, // FS_MODIFY | FS_EVENT_ON_CHILD

						TraceeMntnsId: info.MountNsID,
						TracerMntnsId: utils.NormalizedInt,

						FaType:     utils.NormalizedStr,
						FaResponse: utils.NormalizedStr,

						IWd:     utils.NormalizedInt,
						IIno:    eventDetails.Ino,
						IInoDir: eventDetails.InoDir,

						Name:  eventDetails.FileName,
					}
				})(t, info, 0, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var eventDetails EventDetails
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)

			normalizeEvent := func(event *ExpectedFsnotifyEvent) {
				utils.NormalizeString(&event.Timestamp)
				utils.NormalizeInt(&event.TracerMntnsId)

				utils.NormalizeString(&event.FaType)
				utils.NormalizeString(&event.FaResponse)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
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
				Timeout:        10 * time.Second,
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

	inode, dirInode, err := calculateInodeValues(newFile.Name())
	if err != nil {
		return EventDetails{}, err
	}

	fileName := path.Base(newFile.Name())
	eventDetails := EventDetails{
		FileName: fileName,
		Ino:      uint32(inode),
		InoDir:   uint32(dirInode),
	}
	return eventDetails, nil
}

func calculateInodeValues(fileName string) (uint64, uint64, error) {
	// extract inode info about file
	fileInfo, err := os.Stat(fileName)
	if err != nil {
		return 0, 0, err
	}
	fileSys := fileInfo.Sys()
	var inode uint64
	if stat, ok := fileSys.(*syscall.Stat_t); ok {
		inode = uint64(stat.Ino)
	}
	fmt.Printf("Inode of File: %d\n", inode)

	// extract inode info about directory
	dirInfo, err := os.Stat(path.Dir(fileName))
	if err != nil {
		return 0, 0, err
	}
	dirSys := dirInfo.Sys()
	var dirInode uint64
	if dirStat, ok := dirSys.(*syscall.Stat_t); ok {
		dirInode = uint64(dirStat.Ino)
	}
	fmt.Printf("Inode of Directory: %d\n", dirInode)

	return inode, dirInode, nil
}

