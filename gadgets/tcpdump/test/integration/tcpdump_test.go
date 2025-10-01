// Copyright 2019-2025 The Inspektor Gadget authors
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
	"strings"
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

type tcpdumpEvent struct {
	utils.CommonData

	Timestamp string `json:"timestamp"`
}

const (
	DefaultClientImage = gadgettesting.BusyBoxImage
)

type testCase struct {
	name string

	clientImage string
	clientUID   uint32
	clientGID   uint32
	clientCmds  func(string, uint32, uint32) []string
}

func newTCPDumpStep(t *testing.T, tc testCase) (igtesting.TestStep, []igtesting.Option) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	clientContainerName := fmt.Sprintf("%s-client", tc.name)

	var nsTest string
	clientContainerOpts := []containers.ContainerOption{containers.WithContainerImage(tc.clientImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		nsTest = utils.GenerateTestNamespaceName(t, tc.name)
		testutils.CreateK8sNamespace(t, nsTest)

		clientContainerOpts = append(clientContainerOpts, containers.WithContainerNamespace(nsTest))
		clientContainerOpts = append(clientContainerOpts, containers.WithUseExistingNamespace())
	}

	nslookupCmds := tc.clientCmds("1.1.1.1", tc.clientUID, tc.clientGID)

	clientContainer := containerFactory.NewContainer(
		clientContainerName,
		fmt.Sprintf("while true; do %s; sleep 1; done", strings.Join(nslookupCmds, " ; ")),
		clientContainerOpts...,
	)
	clientContainer.Start(t)
	t.Cleanup(func() {
		clientContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerID(clientContainer.ID())}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		// TODO: skip validation of ContainerImageName because of https://github.com/inspektor-gadget/inspektor-gadget/issues/4104
		commonDataOpts = append(commonDataOpts, utils.WithContainerImageName(utils.NormalizedStr))
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--pf=port 53", "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", nsTest), "--pf=port 53", "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(nsTest)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(nsTest), utils.WithContainerImageName(tc.clientImage))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*tcpdumpEvent{
				// A DNS packet
				{
					CommonData: utils.BuildCommonData(clientContainerName, commonDataOpts...),

					Timestamp: utils.NormalizedStr,
				},
			}

			normalize := func(e *tcpdumpEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)

				if utils.CurrentTestComponent == utils.IgLocalTestComponent {
					utils.NormalizeString(&e.Runtime.ContainerImageName)
				}
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	return igrunner.New("tcpdump", runnerOpts...), testingOpts
}

func TestTCPDump(t *testing.T) {
	t.Parallel()

	clientImage := os.Getenv("TEST_DNS_CLIENT_IMAGE")
	if clientImage == "" {
		clientImage = DefaultClientImage
	}

	tc := testCase{
		name: "test-tcpdump",

		clientImage: clientImage,
		clientUID:   1000,
		clientGID:   1111,
		clientCmds: func(serverIP string, uid, gid uint32) []string {
			return []string{
				fmt.Sprintf("setuidgid %d:%d nslookup -type=a fake.test.com. %s", uid, gid, serverIP),
				fmt.Sprintf("setuidgid %d:%d nslookup -type=aaaa fake.test.com. %s", uid, gid, serverIP),
			}
		},
	}

	tcpDumpCmd, testingOpts := newTCPDumpStep(t, tc)
	igtesting.RunTestSteps([]igtesting.TestStep{tcpDumpCmd}, t, testingOpts...)
}
