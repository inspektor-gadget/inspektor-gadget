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
	"os/user"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
)

type Inner struct {
	InnerEnum       string `json:"inner_enum"`
	InnerEnumRaw    int    `json:"inner_enum_raw"`
	InnerErrno      string `json:"inner_errno"`
	InnerErrnoRaw   int    `json:"inner_errno_raw"`
	InnerGroup      string `json:"inner_group"`
	InnerGroupRaw   int    `json:"inner_group_raw"`
	InnerSyscall    string `json:"inner_syscall"`
	InnerSyscallRaw int    `json:"inner_syscall_raw"`
	InnerUser       string `json:"inner_user"`
	InnerUserRaw    int    `json:"inner_user_raw"`
}

type ExpectedInnerEvent struct {
	Enum       string `json:"enum"`
	EnumRaw    int    `json:"enum_raw"`
	Errno      string `json:"errno"`
	ErrnoRaw   int    `json:"errno_raw"`
	Group      string `json:"group"`
	GroupRaw   int    `json:"group_raw"`
	Inner      Inner  `json:"inner"`
	Syscall    string `json:"syscall"`
	SyscallRaw int    `json:"syscall_raw"`
	User       string `json:"user"`
	UserRaw    int    `json:"user_raw"`
}

func TestInnerFields(t *testing.T) {
	utilstest.RequireRoot(t)

	t.Parallel()

	runnerConfig := &utilstest.RunnerConfig{}
	runner := utilstest.NewRunnerWithTest(t, runnerConfig)

	onGadgetRun := func(gadgetCtx operators.GadgetContext) error {
		utilstest.RunWithRunner(t, runner, generateEvent)
		return nil
	}
	// As this gadget has / on this name, we need to use the full path to avoid
	// a lookup failure when running it.
	image := "ci/inner_fields"
	if _, ok := os.LookupEnv("GADGET_REPOSITORY"); !ok {
		image = fmt.Sprintf("ghcr.io/inspektor-gadget/gadget/%s", image)
	}
	opts := gadgetrunner.GadgetRunnerOpts[ExpectedInnerEvent]{
		Image:       image,
		Timeout:     5 * time.Second,
		OnGadgetRun: onGadgetRun,
	}
	gadgetRunner := gadgetrunner.NewGadgetRunner(t, opts)
	gadgetRunner.RunGadget()

	userInfo, err := user.LookupId(fmt.Sprintf("%d", runner.Info.Uid))
	require.NoError(t, err)
	groupInfo, err := user.LookupGroupId(fmt.Sprintf("%d", runner.Info.Gid))
	require.NoError(t, err)

	utilstest.ExpectAtLeastOneEvent(func(info *utilstest.RunnerInfo, _ int) *ExpectedInnerEvent {
		return &ExpectedInnerEvent{
			Inner: Inner{
				InnerEnum:       "TWO",
				InnerEnumRaw:    2,
				InnerErrno:      "ENOTBLK",
				InnerErrnoRaw:   15,
				InnerGroup:      groupInfo.Name,
				InnerGroupRaw:   0,
				InnerSyscall:    "SYS_LISTEN",
				InnerSyscallRaw: 50,
				InnerUser:       userInfo.Name,
				InnerUserRaw:    0,
			},
			Enum:       "TWO",
			EnumRaw:    2,
			Errno:      "ENOTBLK",
			ErrnoRaw:   15,
			Group:      groupInfo.Name,
			GroupRaw:   0,
			Syscall:    "SYS_LISTEN",
			SyscallRaw: 50,
			User:       userInfo.Name,
			UserRaw:    0,
		}
	})(t, runner.Info, 0, gadgetRunner.CapturedEvents)
}

// generateEvent simulates an event by opening and closing a file
func generateEvent() error {
	fd, err := unix.Open("/dev/null", 0, 0)
	if err != nil {
		return err
	}

	unix.Close(fd)

	return nil
}
