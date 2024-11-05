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
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type ExpectedFdpassEvent struct {
	Proc ebpftypes.Process `json:"proc"`

	SocketIno uint64 `json:"socket_ino"`
	Sockfd    uint32 `json:"sockfd"`
	Fd        uint32 `json:"fd"`
	File      string `json:"file"`
}

type testDef struct {
	runnerConfig   *utilstest.RunnerConfig
	mntnsFilterMap func(info *utilstest.RunnerInfo) *ebpf.Map
	generateEvent  func() (uint64, int, int, error)
	validateEvent  func(t *testing.T, info *utilstest.RunnerInfo, inodeNum uint64, sockfd int, fd int, events []ExpectedFdpassEvent)
}

func TestFdpassGadget(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	testCases := map[string]testDef{
		"basic": {
			runnerConfig:  &utilstest.RunnerConfig{},
			generateEvent: generateEvent,
			validateEvent: func(t *testing.T, info *utilstest.RunnerInfo, inodeNum uint64, sockfd int, fd int, events []ExpectedFdpassEvent) {
				utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, fd int) *ExpectedFdpassEvent {
					return &ExpectedFdpassEvent{
						Proc:      info.Proc,
						SocketIno: inodeNum,
						Sockfd:    uint32(sockfd),
						Fd:        uint32(fd),
						File:      "/dev/null",
					}
				})(t, info, fd, events)
			},
		},
	}
	for name, testCase := range testCases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			var (
				socketIno  uint64
				sockfd, fd int
			)
			runner := utilstest.NewRunnerWithTest(t, testCase.runnerConfig)
			var mntnsFilterMap *ebpf.Map
			if testCase.mntnsFilterMap != nil {
				mntnsFilterMap = testCase.mntnsFilterMap(runner.Info)
			}
			onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
				utilstest.RunWithRunner(t, runner, func() error {
					var err error
					socketIno, sockfd, fd, err = testCase.generateEvent()
					if err != nil {
						return err
					}
					return nil
				})
				return nil
			}
			opts := gadgetrunner.GadgetRunnerOpts[ExpectedFdpassEvent]{
				Image:          "fdpass",
				Timeout:        5 * time.Second,
				MntnsFilterMap: mntnsFilterMap,
				OnGadgetRun:    onGadgetRun,
			}
			gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)

			gadgetRunner.RunGadget()

			testCase.validateEvent(t, runner.Info, socketIno, sockfd, fd, gadgetRunner.CapturedEvents)
		})
	}
}

func generateEvent() (uint64, int, int, error) {
	sockfds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	defer unix.Close(sockfds[0])
	defer unix.Close(sockfds[1])

	var stat unix.Stat_t
	err = unix.Fstat(sockfds[0], &stat)
	if err != nil {
		return 0, 0, 0, err
	}
	inodeNum := stat.Ino

	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return 0, 0, 0, err
	}
	defer unix.Close(fd)

	oob := unix.UnixRights(int(fd))
	err = unix.Sendmsg(sockfds[0], []byte("hello"), oob, nil, 0)
	if err != nil {
		return 0, 0, 0, err
	}

	return inodeNum, sockfds[0], fd, nil
}
