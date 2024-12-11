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
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type snapshotProcessEntry struct {
	utils.CommonData
	utils.Process
}

func TestSnapshotProcess(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-snapshot-process"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-snapshot-process")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"setuidgid 1000:1111 nc -l -p 9090",
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage), utils.WithContainerID(testContainer.ID())}

	// TODO: timeout shouldn't be required. We need to use something big like 5
	// seconds to avoid the message being lost.
	const timeoutParam = "--timeout=5"
	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), timeoutParam))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), timeoutParam))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &snapshotProcessEntry{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Process:    utils.BuildProc("nc", 1000, 1111),
			}

			normalize := func(e *snapshotProcessEntry) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeProc(&e.Process)
			}

			match.MatchEntries(t, match.JSONSingleArrayMode, output, normalize, expectedEntry)
		},
	))

	snashotProcessCmd := igrunner.New("snapshot_process", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{utils.Sleep(5 * time.Second), snashotProcessCmd}, t, testingOpts...)
}
