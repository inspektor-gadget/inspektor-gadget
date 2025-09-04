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

package integration

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

type containerFilteringEvent struct {
	utils.CommonData
}

func TestContainerFiltering(t *testing.T) {
	t.Parallel()

	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-container-filtering"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-container-filtering")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do sleep 1 && cat /etc/hostname >/dev/null; done",
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
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	// TODO: Maybe we should have separate test for each flag
	switch utils.Runtime {
	case containers.RuntimeKubernetes:
		// FIXME: Use --runtime-containername once following issue is fixed
		// https://github.com/inspektor-gadget/inspektor-gadget/issues/4844
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("--k8s-namespace=%s", ns),
				fmt.Sprintf("--k8s-podname=%s", containerName),
				fmt.Sprintf("--k8s-containername=%s", containerName),
			),
		)
	default:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("--runtime-containername=%s", containerName),
			),
		)
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedContainer := &containerFilteringEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
			}

			normalize := func(e *containerFilteringEvent) {
				utils.NormalizeCommonData(&e.CommonData)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedContainer)
		},
	))

	runnerOpts = append(runnerOpts, igrunner.WithStartAndStop())
	containerFilteringCmd := igrunner.New("ci/container_filtering", runnerOpts...)

	testSteps := []igtesting.TestStep{
		containerFilteringCmd,
		utils.Sleep(3 * time.Second),
	}
	igtesting.RunTestSteps(testSteps, t, testingOpts...)
}
