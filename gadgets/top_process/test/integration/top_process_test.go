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
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type topProcessEntry struct {
	utils.CommonData

	Comm        string  `json:"comm"`
	CpuUsage    float64 `json:"cpuUsage"`
	MemoryRSS   uint64  `json:"memoryRSS"`
	State       string  `json:"state"`
	ThreadCount uint32  `json:"threadCount"`
}

func TestTopProcess(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-process"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-top-process")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"nc -l -p 9090",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
		utils.WithContainerID(testContainer.ID()),
	}

	// --count=2: gadget emits after first-interval (250ms) and once more
	// after the regular interval (3s), then exits automatically.
	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(
			fmt.Sprintf("-r=%s", utils.Runtime),
			"--count=2",
		))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(
			fmt.Sprintf("-n=%s", ns),
			"--count=2",
		))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &topProcessEntry{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Comm:       "nc",
			}

			normalize := func(e *topProcessEntry) {
				utils.NormalizeCommonData(&e.CommonData)
				// Zero out runtime-dependent fields that vary between runs
				e.CpuUsage = 0
				e.MemoryRSS = 0
				e.ThreadCount = 0
				e.State = ""
			}

			match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
		},
	))

	topProcessCmd := igrunner.New("top_process", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{
		topProcessCmd,
	}, t, testingOpts...)
}
