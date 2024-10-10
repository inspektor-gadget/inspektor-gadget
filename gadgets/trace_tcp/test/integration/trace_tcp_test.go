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

type traceTCPEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`
	NetNsID   uint64 `json:"netns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Src  utils.L4Endpoint `json:"src"`
	Dst  utils.L4Endpoint `json:"dst"`
	Type string           `json:"type"`
}

func TestTraceTCP(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-tcp"
	containerImage := "docker.io/library/nginx:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-trace-tcp")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	case utils.IgLocalTestComponent:
		containerOpts = append(containerOpts, containers.WithPrivileged())
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
			expectedEntries := []*traceTCPEvent{
				{
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
					Uid:  0,
					Gid:  0,
					Type: "connect",

					// Check only the existence of these fields
					MntNsID:   utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					NetNsID:   utils.NormalizedInt,
				},
				{
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
					Comm: "nginx",
					Uid:  101,
					Gid:  101,
					Type: "accept",

					// Check only the existence of these fields
					MntNsID:   utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					NetNsID:   utils.NormalizedInt,
				},
				{
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
					Uid:  0,
					Gid:  0,
					Type: "close",

					// Check only the existence of these fields
					MntNsID:   utils.NormalizedInt,
					Timestamp: utils.NormalizedStr,
					Pid:       utils.NormalizedInt,
					Tid:       utils.NormalizedInt,
					NetNsID:   utils.NormalizedInt,
				},
			}

			normalize := func(e *traceTCPEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.MntNsID)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.NetNsID)
				// Checking the ports is a little bit complicated as successive
				// calls to curl with --local-port fail because of
				// https://github.com/curl/curl/issues/6288
				utils.NormalizeInt(&e.Src.Port)
				utils.NormalizeInt(&e.Dst.Port)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	traceTCPCmd := igrunner.New("trace_tcp", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceTCPCmd}, t, testingOpts...)
}
