// Copyright 2026 The Inspektor Gadget authors
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

type traceLinkEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	IsSymlink bool   `json:"is_symlink"`
	Target    string `json:"target"`
	LinkPath  string `json:"linkpath"`
}

func TestTraceLink(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-link"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-link")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do touch /tmp/testlinkold ; ln /tmp/testlinkold /tmp/testlinknew ; ln -sfn ../tmp/testlinkold /tmp/testlinksym ; rm -f /tmp/testlinkold /tmp/testlinknew /tmp/testlinksym ; sleep 1; done",
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
			expectedHardlinkEntry := &traceLinkEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proc:       utils.BuildProc("ln", 0, 0),
				IsSymlink:  false,
				Target:     "/tmp/testlinkold",
				LinkPath:   "/tmp/testlinknew",

				// Check the existence of the following fields
				Timestamp: utils.NormalizedStr,
			}

			expectedSymlinkEntry := &traceLinkEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proc:       utils.BuildProc("ln", 0, 0),
				IsSymlink:  true,
				Target:     "../tmp/testlinkold",
				LinkPath:   "/tmp/testlinksym",

				// Check the existence of the following fields
				Timestamp: utils.NormalizedStr,
			}

			normalize := func(e *traceLinkEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeProc(&e.Proc)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize,
				expectedHardlinkEntry, expectedSymlinkEntry)
		},
	))

	traceLinkCmd := igrunner.New("trace_link", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceLinkCmd}, t, testingOpts...)
}
