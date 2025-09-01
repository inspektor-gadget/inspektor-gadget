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
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type topBlockioEntry struct {
	utils.CommonData

	Proc utils.Process `json:"proc"`

	Bytes uint64 `json:"bytes"`
	Io    uint32 `json:"io"`
	Major int    `json:"major"`
	Minor int    `json:"minor"`
	Rw    string `json:"rw"`
	Us    uint64 `json:"us"`
}

func TestTopBlockio(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	gadgettesting.MinimumKernelVersion(t, "6.5")

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-blockio"
	containerImage := gadgettesting.BusyBoxImage

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

	arch := gadgettesting.GetArch(t)
	k8sDistro := os.Getenv("KUBERNETES_DISTRIBUTION")

	// bytes manipulated by dd are given by count * bs
	// where bs is 512 by default and we set 4096 for count
	expectedBytes := uint64(512 * 4096)
	if k8sDistro == gadgettesting.K8sDistroAKSAzureLinux && arch == "arm64" {
		// AzureLinux arm64 does not report the exact same amount of bytes:
		// https://github.com/inspektor-gadget/inspektor-gadget/actions/runs/17369943883/attempts/1#summary-49303962116
		// TODO Investigate this issue.
		expectedBytes = utils.NormalizedInt
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntry := &topBlockioEntry{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("dd", 0, 0),
					Bytes:      expectedBytes,
					Rw:         "write",

					// Check the existence of the following fields
					Us: utils.NormalizedInt,
					Io: utils.NormalizedInt,

					// Manually normalize fields that might contain 0, so we
					// can't use NormalizedInt and NormalizeInt()
					// TODO: Support checking for the presence of a field, even if it's 0
					Major: 0,
					Minor: 0,
				}

				normalize := func(e *topBlockioEntry) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeProc(&e.Proc)
					utils.NormalizeInt(&e.Us)
					utils.NormalizeInt(&e.Io)

					// Manually normalize fields that might contain 0
					e.Major = 0
					e.Minor = 0

					if k8sDistro == gadgettesting.K8sDistroAKSAzureLinux && arch == "arm64" {
						utils.NormalizeInt(&e.Bytes)
					}
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	topBlockioCmd := igrunner.New("top_blockio", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{topBlockioCmd}, t, testingOpts...)
}
