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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/testutils"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type schedCLSDropEvent struct {
	Dir string `json:"dir"`
}

func TestSchedCLS(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	const serverContainerName = "schedcls-server"
	const clientContainerName = "schedcls-client"

	var nsTest string
	serverContainerOpts := []containers.ContainerOption{containers.WithContainerImage(gadgettesting.NginxImage)}
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(gadgettesting.NginxImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		nsTest = utils.GenerateTestNamespaceName(t, "schedcls-test")
		testutils.CreateK8sNamespace(t, nsTest)

		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
		serverContainerOpts = append(serverContainerOpts, containers.WithContainerNamespace(nsTest))
		serverContainerOpts = append(serverContainerOpts, containers.WithUseExistingNamespace())
	}

	serverContainer := containerFactory.NewContainer(
		serverContainerName,
		"nginx && sleep 1000",
		serverContainerOpts...,
	)
	serverContainer.Start(t)
	t.Cleanup(func() {
		serverContainer.Stop(t)
	})

	serverIP := serverContainer.IP()

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		// do not use ping as it requires root privileges and we don't support
		// running test privileged containers in k8s yet
		fmt.Sprintf("while true; do curl %s; sleep 1; done", serverIP),
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	runnerOpts := []igrunner.Option{
		igrunner.WithFlags("'--containername=" + clientContainerName),
	}
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsTest), "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsTest)))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*schedCLSDropEvent{
				{
					Dir: "INGRESS",
				},
				{
					Dir: "EGRESS",
				},
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, nil, expectedEntries...)
		},
	))

	schedClsCmd := igrunner.New("ci/sched_cls_drop", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{schedClsCmd}, t, testingOpts...)
}
