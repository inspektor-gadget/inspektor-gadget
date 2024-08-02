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
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceCapabilitiesEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	CurrentUserNs uint64 `json:"current_user_ns"`
	TargetUserNs  uint64 `json:"target_user_ns"`
	CapEffective  string `json:"cap_effective"`
	Cap           string `json:"cap"`
	Audit         uint32 `json:"audit"`
	Insetid       uint32 `json:"insetid"`
	Syscall       string `json:"syscall"`
	Kstack        string `json:"kstack"`
	Capable       bool   `json:"capable"`
}

func TestTraceCapabilities(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-capabilities"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-capabilities")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do nice -n -20 echo; sleep 0.1; done",
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
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime)))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*traceCapabilitiesEvent{
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Cap:        "CAP_SYS_NICE",
					Syscall:    "SYS_SETPRIORITY",
					Audit:      1,
					Capable:    false,
					Comm:       "nice",

					// Check the existence of the following fields
					MntNsID:       utils.NormalizedInt,
					Timestamp:     utils.NormalizedStr,
					Pid:           utils.NormalizedInt,
					Tid:           utils.NormalizedInt,
					Uid:           0,
					Gid:           0,
					Kstack:        utils.NormalizedStr,
					Insetid:       0,
					CapEffective:  utils.NormalizedStr,
					CurrentUserNs: 0,
					TargetUserNs:  0,
				},
			}

			normalize := func(e *traceCapabilitiesEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.MntNsID)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeString(&e.Kstack)
				utils.NormalizeString(&e.CapEffective)

				// Manually normalize fields that might contain 0
				e.Uid = 0
				e.Gid = 0
				e.CurrentUserNs = 0
				e.TargetUserNs = 0
				e.Insetid = 0
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	runnerOpts = append(runnerOpts, igrunner.WithStartAndStop())
	traceCapabilitiesCmd := igrunner.New("trace_capabilities", runnerOpts...)

	steps := []igtesting.TestStep{
		traceCapabilitiesCmd,
		// wait to ensure ig or kubectl-gadget has started
		utils.Sleep(3 * time.Second),
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
