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

	Pid         uint32 `json:"pid"`
	Comm        string `json:"comm"`
	Uid         uint32 `json:"uid"`
	ThreadCount uint32 `json:"threadCount"`
	State       string `json:"state"`
	Priority    int32  `json:"priority"`
	Nice        int32  `json:"nice"`

	CpuUsage         float64 `json:"cpuUsage"`
	CpuUsageRelative float64 `json:"cpuUsageRelative"`
	CpuTimeStr       string  `json:"cpuTimeStr"`

	MemoryRSS      string  `json:"memoryRSS"`
	MemoryVirtual  string  `json:"memoryVirtual" `
	MemoryShared   string  `json:"memoryShared"`
	MemoryRelative float64 `json:"memoryRelative"`
}

func TestTopProcess(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-process"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-top-process")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"exec nice -n 10 setuidgid 1000:1111 sh -c 'while true; do :; done'",
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

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				fmt.Sprintf("-c=%s", containerName),
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-n=%s", ns),
			),
		)
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &topProcessEntry{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Comm:       "sh",
					Uid:        1000,
					Nice:       10,

					// Testing the existence of these fields
					Pid:           utils.NormalizedInt,
					ThreadCount:   utils.NormalizedInt,
					State:         utils.NormalizedStr,
					Priority:      utils.NormalizedInt,
					CpuTimeStr:    utils.NormalizedStr,
					MemoryRSS:     utils.NormalizedStr,
					MemoryVirtual: utils.NormalizedStr,
					MemoryShared:  utils.NormalizedStr,
				}

				normalize := func(e *topProcessEntry) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeInt(&e.Pid)
					utils.NormalizeInt(&e.ThreadCount)
					utils.NormalizeInt(&e.Priority)
					utils.NormalizeString(&e.State)

					utils.NormalizeString(&e.CpuTimeStr)

					utils.NormalizeString(&e.MemoryRSS)
					utils.NormalizeString(&e.MemoryVirtual)
					utils.NormalizeString(&e.MemoryShared)

					e.CpuUsage = 0.0
					e.CpuUsageRelative = 0.0
					e.MemoryRelative = 0.0
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	topProcessCmd := igrunner.New("top_process", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{topProcessCmd}, t, testingOpts...)
}
