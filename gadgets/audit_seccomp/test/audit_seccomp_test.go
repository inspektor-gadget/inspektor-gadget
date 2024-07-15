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
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type auditSeccompEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Syscall string `json:"syscall"`
	Code    string `json:"code"`
}

var seccompProfile = `
{
    "defaultAction": "SCMP_ACT_ALLOW",
    "syscalls": [
        {
            "names": [
                "unshare"
            ],
            "action": "SCMP_ACT_KILL"
        },
        {
            "names": [
                "mkdir"
            ],
            "action": "SCMP_ACT_LOG"
        }
    ]
}
`

func TestAuditSeccomp(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.Runtime != "docker" {
		t.Skipf("Test requires docker runtime, got: %s", utils.Runtime)
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-audit-seccomp"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
		containers.WithContainerSeccompProfile(seccompProfile),
	}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-audit-seccomp")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do setuidgid 1000:1111 unshare -i; setuidgid 1000:1111 mkdir foo; sleep 1; done",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage), utils.WithContainerID(testContainer.ID())}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*auditSeccompEvent{
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Comm:       "unshare",
					Uid:        1000,
					Gid:        1111,
					Syscall:    "SYS_UNSHARE",
					Code:       "SECCOMP_RET_KILL_THREAD",

					// Check the existence of the following fields
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					MntNsID:   utils.NormalizedInt,
				},
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Comm:       "mkdir",
					Uid:        1000,
					Gid:        1111,
					Syscall:    "SYS_MKDIR",
					Code:       "SECCOMP_RET_LOG",

					// Check the existence of the following fields
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					MntNsID:   utils.NormalizedInt,
				},
			}

			normalize := func(e *auditSeccompEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.MntNsID)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	traceOpenCmd := igrunner.New("audit_seccomp", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceOpenCmd}, t, testingOpts...)
}
