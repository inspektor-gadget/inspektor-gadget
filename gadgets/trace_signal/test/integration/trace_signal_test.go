// Copyright 2019-2024 The Inspektor Gadget authors
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

type traceSignalEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Signal    string `json:"sig"`
	SignalRaw int    `json:"sig_raw"`
	Error     string `json:"error"`
}

func TestTraceSignal(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-signal"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-trace-signal")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do sleep 3 & kill $!; done",
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
			expectedEntry := &traceSignalEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Uid:        0,
				Gid:        0,
				Signal:     "SIGTERM",
				SignalRaw:  15,
				Error:      "",
				Comm:       "sh",

				// Check only the existence of these fields
				Pid:       utils.NormalizedInt,
				Tid:       utils.NormalizedInt,
				Timestamp: utils.NormalizedStr,
				MntNsID:   utils.NormalizedInt,
			}

			normalize := func(e *traceSignalEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.MntNsID)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	traceSignalCmd := igrunner.New("trace_signal", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceSignalCmd}, t, testingOpts...)
}
