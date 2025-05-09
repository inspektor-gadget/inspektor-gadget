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

type adviseNetworkPolicyEvent struct {
	utils.CommonData
	Proc utils.Process `json:"proc"`

	Egress   int              `json:"egress"`
	Endpoint utils.L4Endpoint `json:"endpoint"`
}

func TestAdviseNetworkpolicyGadget(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-advise-networkpolicy"
	containerImage := gadgettesting.NginxImage

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-advise-networkpolicy")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	case utils.IgLocalTestComponent:
		containerOpts = append(containerOpts, containers.WithPrivileged())
	}

	// TODO: can't use setuidgid because it's not available on the nginx image
	testContainer := containerFactory.NewContainer(
		containerName,
		"nginx && while true; do curl 127.0.0.1:80; sleep 0.5; curl inspektor-gadget.io:80; done",
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
			expectedEntries := []*adviseNetworkPolicyEvent{
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("curl", 0, 0),
					Egress:     1,
					Endpoint: utils.L4Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
						Port:    80,
						Proto:   "TCP",
					},
				},
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("nginx", 101, 101),
					Egress:     0,
					Endpoint: utils.L4Endpoint{
						Addr:    "127.0.0.1",
						Version: 4,
						Port:    utils.NormalizedInt,
						Proto:   "TCP",
					},
				},
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("curl", 0, 0),
					Egress:     1,
					Endpoint: utils.L4Endpoint{
						Addr:    "0.0.0.0",
						Version: 4,
						Port:    53,
						Proto:   "UDP",
					},
				},
			}

			normalize := func(e *adviseNetworkPolicyEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeEndpoint(&e.Endpoint)
				utils.NormalizeProc(&e.Proc)
				if e.Egress == 0 {
					utils.NormalizeInt(&e.Endpoint.Port)
				}
				// We don't know the ip addr of the dns resolver
				if e.Endpoint.Proto == "UDP" {
					e.Endpoint.Addr = "0.0.0.0"
				}
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	adviseNetworkPolicyCmd := igrunner.New("advise_networkpolicy", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{adviseNetworkPolicyCmd}, t, testingOpts...)
}
