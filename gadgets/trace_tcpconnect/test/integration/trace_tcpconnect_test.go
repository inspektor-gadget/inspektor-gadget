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
)

type traceTcpconnectEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	Latency     uint64           `json:"latency,omitempty"`
	SrcEndpoint utils.L4Endpoint `json:"src"`
	DstEndpoint utils.L4Endpoint `json:"dst"`
	// error_raw is not taken due to "EINPROGRESS" / 115 error with use of curl.
	// take a look at: https://www.man7.org/linux/man-pages/man2/connect.2.html
}

func TestTraceTcpconnect(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-tcpconnect"
	containerImage := "docker.io/library/nginx:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}
	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-tcpconnect")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}
	cmds := "nginx && while true; do curl 127.0.0.1; sleep 0.1; done"
	testContainer := containerFactory.NewContainer(containerName, cmds, containerOpts...)
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
			expectedEntries := &traceTcpconnectEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proc:       utils.BuildProc("curl", 0, 0),
				SrcEndpoint: utils.L4Endpoint{
					Addr:    "127.0.0.1",
					Version: 4,
					Port:    utils.NormalizedInt,
					Proto:   "TCP",
				},
				DstEndpoint: utils.L4Endpoint{
					Addr:    "127.0.0.1",
					Version: 4,
					Port:    80,
					Proto:   "TCP",
				},
				Timestamp: utils.NormalizedStr,
			}

			normalize := func(e *traceTcpconnectEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeProc(&e.Proc)
				utils.NormalizeInt(&e.SrcEndpoint.Port)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries)
		},
	))
	traceTcpconnectCmd := igrunner.New("trace_tcpconnect", runnerOpts...)
	steps := []igtesting.TestStep{
		traceTcpconnectCmd,
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
