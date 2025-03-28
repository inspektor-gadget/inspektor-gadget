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
)

type traceloopEvent struct {
	utils.CommonData

	MntnsID    uint64 `json:"mntns_id"`
	CPU        uint16 `json:"cpu"`
	PID        uint32 `json:"pid"`
	Comm       string `json:"comm"`
	Syscall    string `json:"syscall"`
	Parameters string `json:"parameters"`
	Ret        string `json:"ret"`
}

func TestTraceloop(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-traceloop"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		t.Skip("Skipping test as datasource containers was not ported to kubemanager")
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-traceloop")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do ls > /dev/null; sleep 0.1; done",
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
			expectedEntry := &traceloopEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				MntnsID:    utils.NormalizedInt,
				CPU:        utils.NormalizedInt,
				PID:        utils.NormalizedInt,
				Comm:       "ls",
				Syscall:    "write",
				Parameters: utils.NormalizedStr,
				Ret:        utils.NormalizedStr,
			}

			normalize := func(e *traceloopEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.MntnsID)
				utils.NormalizeInt(&e.CPU)
				utils.NormalizeInt(&e.PID)
				utils.NormalizeString(&e.Parameters)
				utils.NormalizeString(&e.Ret)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	// Use timeout to simulate Ctrl^C.
	runnerOpts = append(runnerOpts, igrunner.WithFlags("--timeout=10"))
	traceloopContainersCmd := igrunner.New("traceloop", runnerOpts...)

	steps := []igtesting.TestStep{
		traceloopContainersCmd,
		// wait to ensure ig or kubectl-gadget has started
		utils.Sleep(3 * time.Second),
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
