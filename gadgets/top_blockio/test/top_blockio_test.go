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

	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type topBlockioEntry struct {
	eventtypes.CommonData

	MntNsID uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`

	Bytes uint64 `json:"bytes"`
	Io    uint32 `json:"io"`
	Major int    `json:"major"`
	Minor int    `json:"minor"`
	Rw    string `json:"rw"`
	Us    uint64 `json:"us"`
}

func TestTopBlockio(t *testing.T) {
	version, err := kernel.GetKernelVersion()
	require.Nil(t, err, "Failed to get kernel version: %s", err)
	v6_5 := kernel.VersionInfo{Kernel: 6, Major: 5, Minor: 0}
	if kernel.CompareKernelVersion(*version, v6_5) < 0 {
		t.Skip("Skip running top_blockio on kernel versions lower than 6.5")
	}

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-blockio"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-top-blockio")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do dd if=/dev/zero of=/tmp/test count=4096; sleep 0.2; done",
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
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &topBlockioEntry{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),

					Comm: "dd",
					// bytes manipulated by dd are given by count * bs
					// where bs is 512 by default and we set 4096 for count
					Bytes: 512 * 4096,
					Rw:    "write",

					// Check the existence of the following fields
					MntNsID: utils.NormalizedInt,
					Pid:     utils.NormalizedInt,
					Tid:     utils.NormalizedInt,
					Us:      utils.NormalizedInt,
					Io:      utils.NormalizedInt,

					// Manually normalize fields that might contain 0, so we
					// can't use NormalizedInt and NormalizeInt()
					// TODO: Support checking for the presence of a field, even if it's 0
					Major: 0,
					Minor: 0,
				}

				normalize := func(e *topBlockioEntry) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeInt(&e.MntNsID)
					utils.NormalizeInt(&e.Pid)
					utils.NormalizeInt(&e.Tid)
					utils.NormalizeInt(&e.Us)
					utils.NormalizeInt(&e.Io)

					// Manually normalize fields that might contain 0
					e.Major = 0
					e.Minor = 0
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	topBlockioCmd := igrunner.New("top_blockio", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{topBlockioCmd}, t, testingOpts...)
}
