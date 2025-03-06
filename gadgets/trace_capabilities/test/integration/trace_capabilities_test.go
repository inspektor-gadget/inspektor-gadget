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
	"encoding/base64"
	"fmt"
	"strings"
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

type ustack struct {
	Symbols string `json:"symbols"`
}

type traceCapabilitiesEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	CurrentUserNs uint64 `json:"current_user_ns"`
	TargetUserNs  uint64 `json:"target_user_ns"`
	CapEffective  string `json:"cap_effective"`
	Cap           string `json:"cap"`
	Audit         uint32 `json:"audit"`
	Insetid       uint32 `json:"insetid"`
	Syscall       string `json:"syscall"`
	Kstack        string `json:"kstack"`
	Ustack        ustack `json:"ustack"`
	Capable       bool   `json:"capable"`
}

func TestTraceCapabilities(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// see https://github.com/inspektor-gadget/inspektor-gadget/issues/4093
	gadgettesting.SkipK8sDistros(t, gadgettesting.K8sDistroAKSAzureLinux,
		gadgettesting.K8sDistroAKSUbuntu, gadgettesting.K8sDistroEKSAmazonLinux)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-capabilities"
	containerImage := gadgettesting.GccImage

	execProgram := `
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

__attribute__((noinline)) void level3() {
    chroot("/");
}
__attribute__((noinline)) void level2() {
    level3();
}
__attribute__((noinline)) void level1() {
    level2();
}

int main() {
    level1();
    sleep(4);
    return 0;
}
`
	progBase64 := base64.StdEncoding.EncodeToString([]byte(execProgram))

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-capabilities")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	buildCmd := fmt.Sprintf("echo %s | base64 -d > chroot.c && gcc -Wall -static -o /bin/mychroot chroot.c", progBase64)
	innerCmd := "while true; do /bin/mychroot ; nice -n -20 echo; sleep 0.1; done"
	testContainer := containerFactory.NewContainer(
		containerName,
		fmt.Sprintf("%s ; %s", buildCmd, innerCmd),
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{utils.WithContainerImageName(containerImage), utils.WithContainerID(testContainer.ID())}

	ustackFlag := "--print-ustack=true"
	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), ustackFlag))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), ustackFlag))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntries := []*traceCapabilitiesEvent{
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("mychroot", 0, 0),
					Cap:        "CAP_SYS_CHROOT",
					Syscall:    "SYS_CHROOT",
					Audit:      1,
					Capable:    false,            // container runtime dependent. See normalize function.
					Ustack:     ustack{"level2"}, // normalize() just checks for the presence of this string

					// Check the existence of the following fields
					Timestamp:     utils.NormalizedStr,
					Kstack:        utils.NormalizedStr,
					Insetid:       0,
					CapEffective:  utils.NormalizedStr,
					CurrentUserNs: 0,
					TargetUserNs:  0,
				},
				{
					CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
					Proc:       utils.BuildProc("nice", 0, 0),
					Cap:        "CAP_SYS_NICE",
					Syscall:    "SYS_SETPRIORITY",
					Audit:      1,
					Capable:    false,
					Ustack:     ustack{""},

					// Check the existence of the following fields
					Timestamp:     utils.NormalizedStr,
					Kstack:        utils.NormalizedStr,
					Insetid:       0,
					CapEffective:  utils.NormalizedStr,
					CurrentUserNs: 0,
					TargetUserNs:  0,
				},
			}

			normalize := func(e *traceCapabilitiesEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeString(&e.Timestamp)
				utils.NormalizeProc(&e.Proc)
				utils.NormalizeString(&e.Kstack)
				utils.NormalizeString(&e.CapEffective)

				if e.Proc.Comm == "mychroot" {
					if strings.Contains(e.Ustack.Symbols, "level2") {
						e.Ustack.Symbols = "level2"
					}

					// The default capabilities vary between container runtimes:
					// - cri-o:
					//   https://github.com/cri-o/cri-o/blob/v1.32.1/install.md?plain=1#L538-L548
					// - docker:
					//   https://github.com/moby/moby/blob/v27.5.1/oci/caps/defaults.go#L17
					// - containerd:
					//   https://github.com/containerd/containerd/blob/v2.0.2/pkg/oci/spec.go#L131
					//
					// Docker and containerd gives CAP_SYS_CHROOT but not
					// CRI-O. So we can't predict whether the workload will be
					// able to chroot.
					e.Capable = false
				} else {
					e.Ustack.Symbols = ""
				}

				// Manually normalize fields that might contain 0
				e.CurrentUserNs = 0
				e.TargetUserNs = 0
				e.Insetid = 0
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
		},
	))

	runnerOpts = append(runnerOpts, igrunner.WithStartAndStop())
	traceCapabilitiesCmd := igrunner.New("trace_capabilities", runnerOpts...)

	steps := []igtesting.TestStep{
		traceCapabilitiesCmd,
		// wait to ensure ig or kubectl-gadget has started
		utils.Sleep(3 * time.Second),
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
