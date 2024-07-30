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
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceExecEvent struct {
	eventtypes.CommonData

	Timestamp string `json:"timestamp"`
	MntNsID   uint64 `json:"mntns_id"`

	Comm string `json:"comm"`
	Pid  uint32 `json:"pid"`
	Tid  uint32 `json:"tid"`
	Uid  uint32 `json:"uid"`
	Gid  uint32 `json:"gid"`

	Pcomm       string `json:"pcomm"`
	Ppid        uint32 `json:"ppid"`
	Loginuid    uint32 `json:"loginuid"`
	Sessionid   uint32 `json:"sessionid"`
	Error       string `json:"error"`
	UpperLayer  bool   `json:"upper_layer"`
	PupperLayer bool   `json:"pupper_layer"`
	Cwd         string `json:"cwd"`
	Args        string `json:"args"`
}

func TestTraceExec(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-exec"
	containerImage := "docker.io/library/busybox:latest"

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
		containers.WithStartAndStop(),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-exec")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	sleepArgs := []string{"/bin/sleep", "1"}
	innerCmd := fmt.Sprintf("cd tmp ; while true ; do %s; done", strings.Join(sleepArgs, " "))
	// copies /bin/sh to /usr/bin/sh to check that the upper_layer is true when executing /usr/bin/sh
	cmd := fmt.Sprintf("cp /bin/sh /usr/bin/sh ; setuidgid 1000:1111 /usr/bin/sh -c '%s'", innerCmd)
	shArgs := []string{"/bin/sh", "-c", cmd}
	innerShArgs := []string{"/usr/bin/sh", "-c", innerCmd}

	testContainer := containerFactory.NewContainer(containerName, cmd, containerOpts...)

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
		// TODO: We need to start the container after the tracer, so we don't
		// have the container ID available here. It could be possible to split
		// the logic to have a container create + container start to be able to
		// get the ID before starting it.
		utils.WithContainerID(utils.NormalizedStr),
	}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime)))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithFlags("--paths"),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntries := []*traceExecEvent{
					// outer sh
					{
						CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
						Comm:       "sh",
						Cwd:        "/",
						Args:       strings.Join(shArgs, " "),
						UpperLayer: false,

						// Check the existence of the following fields
						MntNsID:   utils.NormalizedInt,
						Timestamp: utils.NormalizedStr,
						Pid:       utils.NormalizedInt,
						Tid:       utils.NormalizedInt,
						Ppid:      utils.NormalizedInt,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
						Pcomm:     utils.NormalizedStr,
					},
					// inner sh
					{
						CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
						Comm:       "sh",
						Cwd:        "/",
						Args:       strings.Join(innerShArgs, " "),
						Uid:        1000,
						Gid:        1111,
						UpperLayer: true,

						// Check the existence of the following fields
						MntNsID:   utils.NormalizedInt,
						Timestamp: utils.NormalizedStr,
						Pid:       utils.NormalizedInt,
						Tid:       utils.NormalizedInt,
						Ppid:      utils.NormalizedInt,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
						Pcomm:     utils.NormalizedStr,
					},
					// sleep
					{
						CommonData:  utils.BuildCommonData(containerName, commonDataOpts...),
						Comm:        "sleep",
						Cwd:         "/tmp",
						Pcomm:       "sh",
						Args:        strings.Join(sleepArgs, " "),
						Uid:         1000,
						Gid:         1111,
						UpperLayer:  false,
						PupperLayer: true,

						// Check the existence of the following fields
						MntNsID:   utils.NormalizedInt,
						Timestamp: utils.NormalizedStr,
						Pid:       utils.NormalizedInt,
						Tid:       utils.NormalizedInt,
						Ppid:      utils.NormalizedInt,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
				}
				normalize := func(e *traceExecEvent) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeString(&e.Runtime.ContainerID)
					utils.NormalizeInt(&e.MntNsID)
					utils.NormalizeString(&e.Timestamp)
					utils.NormalizeInt(&e.Pid)
					utils.NormalizeInt(&e.Tid)
					utils.NormalizeInt(&e.Ppid)
					utils.NormalizeInt(&e.Loginuid)
					utils.NormalizeInt(&e.Sessionid)

					// We can't know the parent process of the first process inside
					// the container as it depends on the container runtime
					if e.Comm == "sh" || e.Pcomm == "containerd-shim" {
						utils.NormalizeString(&e.Pcomm)
					}
				}
				match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntries...)
			},
		))

	runnerOpts = append(runnerOpts, igrunner.WithStartAndStop())
	traceExecCmd := igrunner.New("trace_exec", runnerOpts...)

	steps := []igtesting.TestStep{
		traceExecCmd,
		// wait to ensure ig or kubectl-gadget has started
		utils.Sleep(10 * time.Second),
		testContainer,
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
