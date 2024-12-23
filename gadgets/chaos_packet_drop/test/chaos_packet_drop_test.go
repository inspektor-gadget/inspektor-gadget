// Copyright 2019-2024 The Inspektor Gadget authors
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

type packetDropEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp,omitempty"`
	NetNsID   uint64 `json:"netns_id"`

	Proc utils.Process `json:"proc"`

	Egress    bool             `json:"egress"`
	Ingress   bool             `json:"ingress"`
	DropCount uint64           `json:"drop_cnt"`
	Src       utils.L4Endpoint `json:"src"`
	Dst       utils.L4Endpoint `json:"dst"`
}

func TestPacketDrop(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-chaos-packet-drop"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-chaos-packet-drop")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	/* Here, we test by downloading a test file of 200MB from download.thinkbroadband.com
	We run the choas_packet_drop gadget while opening a TCP connection to the server
	and hence test the gadget. But in the worst case the gadget fails, we delete the 200MB
	file before downloading again. 

	will shift the server to an another ngnix container servering the file  */

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do wget --user-agent='Mozilla/5.0' http://download.thinkbroadband.com/200MB.zip -O /tmp/200MB.zip && rm -f /tmp/200MB.zip; done",
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
				"--verify-image=false",
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
				expectedEntry := &packetDropEvent{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),

					Dst: utils.L4Endpoint{
						Addr:    "80.249.99.148",
						Version: 4,
						Port:    utils.NormalizedInt,
						Proto:   "TCP",
					},
					Src: utils.L4Endpoint{
						Addr:    utils.NormalizedStr,
						Version: 4,
						Port:    utils.NormalizedInt,
						Proto:   "TCP",
					},
					Ingress:   false,
					Egress:    true,
					Timestamp: utils.NormalizedStr,
					Proc: utils.Process{
						Comm:    utils.NormalizedStr,
						Pid:     utils.NormalizedInt,
						Tid:     utils.NormalizedInt,
						MntNsID: utils.NormalizedInt,
					},
					NetNsID:   utils.NormalizedInt,
					DropCount: utils.NormalizedInt,
				}

				normalize := func(e *packetDropEvent) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeString(&e.Src.Addr)
					utils.NormalizeInt(&e.DropCount)
					utils.NormalizeInt(&e.Proc.Pid)
					utils.NormalizeString(&e.Proc.Comm)
					utils.NormalizeInt(&e.Proc.Tid)
					utils.NormalizeInt(&e.Proc.MntNsID)
					utils.NormalizeInt(&e.Src.Port)
					utils.NormalizeInt(&e.Dst.Port)
					utils.NormalizeString(&e.Timestamp)
					utils.NormalizeInt(&e.NetNsID)
				}

				match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntry)
			},
		))

	pktDropCmd := igrunner.New("chaos_packet_drop", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{pktDropCmd}, t, testingOpts...)
}
