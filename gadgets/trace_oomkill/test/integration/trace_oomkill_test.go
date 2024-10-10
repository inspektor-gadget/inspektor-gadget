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

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceOomKillEvent struct {
	eventtypes.CommonData

	Fpid      uint32 `json:"fpid"`
	Fuid      uint32 `json:"fuid"`
	Fgid      uint32 `json:"fgid"`
	Tpid      uint32 `json:"tpid"`
	Pages     uint64 `json:"pages"`
	MntNsID   uint64 `json:"mntns_id"`
	Timestamp string `json:"timestamp"`
	Fcomm     string `json:"fcomm"`
	Tcomm     string `json:"tcomm"`
}

func TestTraceOomKill(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.KubectlGadgetTestComponent && utils.CurrentTestComponent != utils.IgK8sTestComponent {
		// We have no general way to enforce memory limits for all container runtimes
		t.Skip("Test only runs for kubectl-gadget and ig-k8s")
	}

	containerFactory := &containers.K8sManager{}
	containerName := "test-trace-oomkill"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-oomkill")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	containerOpts = append(containerOpts, containers.WithLimits(map[string]string{"memory": "128Mi"}), containers.WithStartAndStop(), containers.WithWaitOrOomKilled())

	testContainer := containerFactory.NewContainer(
		containerName,
		"while true; do tail /dev/zero; done",
		containerOpts...,
	)

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage)}

	switch utils.CurrentTestComponent {
	case utils.IgK8sTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime)), igrunner.WithStartAndStop())
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)), igrunner.WithStartAndStop())
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceOomKillEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Tcomm:      "tail",

				// Check the existence of the following fields
				Timestamp: utils.NormalizedStr,
				MntNsID:   utils.NormalizedInt,
				Fpid:      utils.NormalizedInt,
				Fuid:      utils.NormalizedInt,
				Fgid:      utils.NormalizedInt,
				Tpid:      utils.NormalizedInt,
				Pages:     utils.NormalizedInt,
				Fcomm:     utils.NormalizedStr,
			}
			expectedEntry.Runtime.ContainerID = utils.NormalizedStr

			normalize := func(e *traceOomKillEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Runtime.ContainerID)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeInt(&e.MntNsID)
				utils.NormalizeInt(&e.Fpid)
				utils.NormalizeInt(&e.Tpid)
				utils.NormalizeInt(&e.Pages)
				utils.NormalizeString(&e.Fcomm)

				// NormalizeInt only normalizes if the value is not 0
				// Fuid and Fgid might be 0, so do the normalization manually
				e.Fuid = utils.NormalizedInt
				e.Fgid = utils.NormalizedInt
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	traceOomkillCmd := igrunner.New("trace_oomkill", runnerOpts...)

	testSteps := []igtesting.TestStep{
		traceOomkillCmd,
		utils.Sleep(10 * time.Second),
		testContainer,
	}

	igtesting.RunTestSteps(testSteps, t, testingOpts...)
}
