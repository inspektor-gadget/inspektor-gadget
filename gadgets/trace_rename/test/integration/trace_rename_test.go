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
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

type traceRenameEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	OldName string `json:"oldname"`
	NewName string `json:"newname"`
	OldPath string `json:"oldpath"`
	NewPath string `json:"newpath"`
	Flags   string `json:"flags"`
}

func TestTraceRename(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-rename"
	containerImage := gadgettesting.BusyBoxImage

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-rename")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	// The failing mv (missing source) must not produce an event; this is
	// checked explicitly below since MatchEntries only matches a subset.
	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do touch /tmp/renameold ; mv /tmp/renameold /tmp/renamenew ; mv /tmp/missing /tmp/x 2>/dev/null ; rm -f /tmp/renamenew ; sleep 1; done",
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
		runnerOpts = append(runnerOpts, igrunner.WithFlags("--paths", fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=5"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags("--paths", fmt.Sprintf("-n=%s", ns), "--timeout=5"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceRenameEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Proc:       utils.BuildProc("mv", 0, 0),
				OldName:    "/tmp/renameold",
				NewName:    "/tmp/renamenew",
				// Paths as seen inside the container
				OldPath: "/tmp/renameold",
				NewPath: "/tmp/renamenew",
				Flags:   "",

				// Check the existence of the following fields
				Timestamp: utils.NormalizedStr,
			}

			normalize := func(e *traceRenameEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeProc(&e.Proc)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)

			for _, line := range strings.Split(output, "\n") {
				var e traceRenameEvent
				if json.Unmarshal([]byte(line), &e) != nil {
					continue
				}
				require.NotEqual(t, "/tmp/missing", e.OldName, "failed rename must not produce an event")
			}
		},
	))

	traceRenameCmd := igrunner.New("trace_rename", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceRenameCmd}, t, testingOpts...)
}
