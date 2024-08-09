// Copyright 2019-2024 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
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

type snapshotSocketEntry struct {
	eventtypes.CommonData

	NetNsID     uint64 `json:"netns_id"`
	InodeNumber uint64 `json:"ino"`

	SrcEndpoint utils.L4Endpoint `json:"src"`
	DstEndpoint utils.L4Endpoint `json:"dst"`
	Status      uint64           `json:"status"`
}

func TestSnapshotSocket(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-snapshot-socket"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-snapshot-socket")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"nc -l 0.0.0.0 -p 9090",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage), utils.WithContainerID(testContainer.ID())}

	// TODO: timeout shouldn't be required
	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=1"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), "--timeout=1"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &snapshotSocketEntry{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				SrcEndpoint: utils.L4Endpoint{
					Addr:    "0.0.0.0",
					Version: 4,
					Port:    9090,
					Proto: 6,
				},
				DstEndpoint: utils.L4Endpoint{
					Addr:    "0.0.0.0",
					Version: 4,
					Port:    0,
				},
				Status:      10,
				NetNsID:     utils.NormalizedInt,
				InodeNumber: utils.NormalizedInt,
			}

			normalize := func(e *snapshotSocketEntry) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.NetNsID)
				utils.NormalizeInt(&e.InodeNumber)
			}

			match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
		},
	))

	snashotSocketCmd := igrunner.New("snapshot_socket", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{snashotSocketCmd}, t, testingOpts...)
}
