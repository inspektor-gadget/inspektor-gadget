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

type traceFSSlowerEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Delta  uint64 `json:"delta_us"`
	Offset uint64 `json:"offset"`
	Size   uint64 `json:"size"`
	Op     string `json:"op"`
	File   string `json:"file"`
}

func TestTraceFSSlower(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// TODO: Take into consideration aro and others
	fsType := "ext4"
	//if *k8sDistro == K8sDistroARO || *k8sDistro == K8sDistroEKSAmazonLinux {
	//	fsType = "xfs"
	//}

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-fsslower"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-fsslower")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"echo 'this is foo' > foo && while true; do cat foo && sleep 0.1; done",
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

	runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-f=%s", fsType), "--min=0"))

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceFSSlowerEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Comm:       "cat",
				File:       "foo",
				Op:         "F_OPEN",
				Offset:     0,
				Size:       0,

				// Check the existence of the following fields
				Timestamp: utils.NormalizedStr,
				Pid:       utils.NormalizedInt,
				Tid:       utils.NormalizedInt,
				MntNsID:   utils.NormalizedInt,
				Delta:     utils.NormalizedInt,
			}

			normalize := func(e *traceFSSlowerEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.Pid)
				utils.NormalizeInt(&e.Tid)
				utils.NormalizeInt(&e.MntNsID)
				utils.NormalizeInt(&e.Delta)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	traceFSSlowerCmd := igrunner.New("trace_fsslower", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceFSSlowerCmd}, t, testingOpts...)
}
