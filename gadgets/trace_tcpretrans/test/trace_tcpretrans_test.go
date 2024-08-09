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

type traceTCPretransEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`
	NetNs     uint64 `json:"netns_id"`

	Pid uint32 `json:"pid"`
	Tid uint32 `json:"tid"`
	Uid uint32 `json:"uid"`
	Gid uint32 `json:"gid"`

	Comm string           `json:"comm"`
	Type string           `json:"type"`
	Src  utils.L4Endpoint `json:"src"`
	Dst  utils.L4Endpoint `json:"dst"`
}

func TestTraceTCPretrans(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		t.Skip("Skipping test as K8s doesn't support privileged containers")
	} else if utils.CurrentTestComponent == utils.IgLocalTestComponent && utils.Runtime == "containerd" {
		t.Skip("Skipping test as containerd test utils can't use the network")
	}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-tcpretrans"
	containerImage := "docker.io/wbitt/network-multitool:latest"

	var ns string
	// run the container with privileged mode to be able to use tc command
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage), containers.WithPrivileged()}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-tcpretrans")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}
	// for testing purpose drop 30% of packets and wget 1.1.1.1 every 0.1 seconds
	cmds := "tc qdisc add dev eth0 root netem drop 30% && while true; do wget --no-check-certificate -q -O /dev/null https://1.1.1.1; sleep 0.1; done"
	testContainer := containerFactory.NewContainer(
		containerName,
		cmds,
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
			expectedEntries := &traceTCPretransEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Src: utils.L4Endpoint{
					Addr:    utils.NormalizedStr,
					Version: 4,
					Port:    utils.NormalizedInt,
					Proto:   6,
				},
				Dst: utils.L4Endpoint{
					Addr:    "1.1.1.1",
					Version: 4,
					Port:    443,
					Proto:   6,
				},
				Uid: 0,
				Gid: 0,

				Comm: "wget",
				Type: "RETRANS",

				Timestamp: utils.NormalizedStr,
				MntNsID:   utils.NormalizedInt,
				NetNs:     utils.NormalizedInt,
				Pid:       utils.NormalizedInt,
				Tid:       utils.NormalizedInt,
			}
			normalize := func(e *traceTCPretransEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.MntNsID)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.NetNs)
				utils.NormalizeString(&e.Src.Addr)
				utils.NormalizeInt(&e.Src.Port)
			}
			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries)
		},
	))
	traceTCPCmd := igrunner.New("trace_tcpretrans", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceTCPCmd}, t, testingOpts...)
}
