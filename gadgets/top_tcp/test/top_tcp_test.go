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

type topTcpEntry struct {
	eventtypes.CommonData

	MntNsID uint64 `json:"mntns_id"`

	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Comm string `json:"comm"`

	Src utils.L4Endpoint `json:"src"`
	Dst utils.L4Endpoint `json:"dst"`

	// Sent and Received might be 0, so we can't use NormalizedInt and NormalizeInt()
	// TODO: Support checking for the presence of a field, even if it's 0
	// Sent     uint64 `json:"sent"`
	// Received uint64 `json:"received"`
}

func TestTopTcp(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-top-tcp"
	containerImage := "docker.io/library/nginx:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-top-tcp")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	// TODO: can't use setuidgid because it's not available on the nginx image
	testContainer := containerFactory.NewContainer(
		containerName,
		"nginx && while true; do curl 127.0.0.1; sleep 0.1; done",
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
				expectedEntry := &topTcpEntry{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),

					Src: utils.L4Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
						Port:    utils.NormalizedInt,
						Proto:   6,
					},
					Dst: utils.L4Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
						Port:    utils.NormalizedInt,
						Proto:   6,
					},
					Comm: "curl",

					// Check the existence of the following fields
					MntNsID: utils.NormalizedInt,
					Pid:     utils.NormalizedInt,
					Tid:     utils.NormalizedInt,
				}

				normalize := func(e *topTcpEntry) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeInt(&e.MntNsID)
					utils.NormalizeInt(&e.Pid)
					utils.NormalizeInt(&e.Tid)
					utils.NormalizeInt(&e.Src.Port)
					utils.NormalizeInt(&e.Dst.Port)
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		),
	)

	topTcpCmd := igrunner.New("top_tcp", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{topTcpCmd}, t, testingOpts...)
}
