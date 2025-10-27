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

type traceExecEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	Loginuid      uint32 `json:"loginuid"`
	Sessionid     uint32 `json:"sessionid"`
	Error         string `json:"error"`
	UpperLayer    bool   `json:"upper_layer"`
	PupperLayer   bool   `json:"pupper_layer"`
	FupperLayer   bool   `json:"fupper_layer"`
	Exepath       string `json:"exepath"`
	File          string `json:"file"`
	Cwd           string `json:"cwd"`
	Args          string `json:"args"`
	DevMajor      uint32 `json:"dev_major"`
	DevMinor      uint32 `json:"dev_minor"`
	Inode         uint64 `json:"inode"`
	ParentExepath string `json:"parent_exepath"`
}

func TestTraceExec(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	// see https://github.com/inspektor-gadget/inspektor-gadget/issues/4094
	gadgettesting.SkipK8sDistros(t, gadgettesting.K8sDistroGKECOS)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")
	containerName := "test-trace-exec"
	containerImage := gadgettesting.GccImage

	execProgram := `
#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>

int main(int argc, char *argv[], char **envp) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <program_to_execute>\n", argv[0]);
        exit(1);
    }

    char *method = getenv("METHOD");
    if (method == NULL) {
        fprintf(stderr, "Environment variable METHOD not set.\n");
        exit(1);
    }

    if (strcmp(method, "execve") == 0) {
        execve(argv[1], argv+1, envp);
        perror("execve");
    } else if (strcmp(method, "execveat") == 0) {
        int fd = open(".", O_RDONLY | O_DIRECTORY);
        if (fd == -1) {
            perror("open");
            exit(1);
        }

        execveat(fd, argv[1], argv+1, envp, 0);
        perror("execveat");
    } else {
        fprintf(stderr, "Invalid value for METHOD environment variable.\n");
    }
    exit(1);
}
`
	progBase64 := base64.StdEncoding.EncodeToString([]byte(execProgram))

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
		containers.WithStartAndStop(),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-trace-exec")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	buildCmd := fmt.Sprintf("echo %s | base64 -d > exec.c && gcc -Wall -o /bin/exec-syscall exec.c", progBase64)
	prepareScriptsCmd := "printf '#!/bin/sh\nls' > /bin/with_shebeng.sh ; echo ls > /dev/script.sh ; echo ls > /bin/script.sh ; chmod +x /dev/script.sh /bin/script.sh /bin/with_shebeng.sh ; "
	sleep1Args := []string{"/usr/bin/sleep", "0.4"}
	sleep2Args := []string{"/usr/bin/sleep", "0.6"}
	execScriptsCmd := "/dev/script.sh ; /bin/script.sh ; /bin/with_shebeng.sh"
	innerCmd := fmt.Sprintf(
		"cd tmp ; while true ; do METHOD=execve exec-syscall %s; METHOD=execveat exec-syscall %s; %s; done",
		strings.Join(sleep1Args, " "),
		strings.Join(sleep2Args, " "),
		execScriptsCmd,
	)
	// copies /usr/bin/sh to /usr/bin/sh2 to check that the upper_layer is true when executing /usr/bin/sh2
	cmd := fmt.Sprintf("%s %s && cp /usr/bin/sh /usr/bin/sh2 && setpriv --reuid 1000 --regid 1111 --clear-groups /usr/bin/sh2 -c '%s'", prepareScriptsCmd, buildCmd, innerCmd)
	innerShArgs := []string{"/usr/bin/sh2", "-c", innerCmd}

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
		igrunner.WithFlags("--paths", "--ignore-failed=false"),
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				expectedEntries := []*traceExecEvent{
					// inner script.sh
					{
						CommonData:  utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:        utils.BuildProc("sh2", 1000, 1111),
						Cwd:         "/tmp",
						Args:        "/dev/script.sh",
						PupperLayer: false,
						UpperLayer:  false,
						FupperLayer: false,
						Exepath:     "/usr/bin/sh2",
						File:        "/dev/script.sh",
						Error:       "ENOEXEC",
						DevMajor:    utils.NormalizedInt,
						DevMinor:    utils.NormalizedInt,
						Inode:       utils.NormalizedInt,

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
					{
						CommonData:  utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:        utils.BuildProc("sh2", 1000, 1111),
						Cwd:         "/tmp",
						Args:        "/bin/script.sh",
						PupperLayer: false,
						UpperLayer:  false,
						FupperLayer: true,
						Exepath:     "/usr/bin/sh2",
						File:        "/usr/bin/script.sh",
						Error:       "ENOEXEC",
						DevMajor:    utils.NormalizedInt,
						DevMinor:    utils.NormalizedInt,
						Inode:       utils.NormalizedInt,

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
					{
						CommonData:    utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:          utils.BuildProc("with_shebeng.sh", 1000, 1111),
						Cwd:           "/tmp",
						Args:          "/bin/with_shebeng.sh",
						PupperLayer:   true,
						UpperLayer:    false,
						FupperLayer:   true,
						Exepath:       "/usr/bin/dash",
						File:          "/usr/bin/with_shebeng.sh",
						Error:         "",
						DevMajor:      utils.NormalizedInt,
						DevMinor:      utils.NormalizedInt,
						Inode:         utils.NormalizedInt,
						ParentExepath: "/usr/bin/sh2",

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
					// inner sh
					{
						CommonData:    utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:          utils.BuildProc("sh2", 1000, 1111),
						Cwd:           "/",
						Args:          strings.Join(innerShArgs, " "),
						PupperLayer:   false,
						UpperLayer:    true,
						FupperLayer:   true,
						Exepath:       "/usr/bin/sh2",
						File:          "/usr/bin/sh2",
						DevMajor:      utils.NormalizedInt,
						DevMinor:      utils.NormalizedInt,
						Inode:         utils.NormalizedInt,
						ParentExepath: "/usr/bin/dash",

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
					// sleeps
					{
						CommonData:    utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:          utils.BuildProc("sleep", 1000, 1111),
						Cwd:           "/tmp",
						Args:          strings.Join(sleep1Args, " "),
						PupperLayer:   true,
						UpperLayer:    false,
						FupperLayer:   false,
						Exepath:       "/usr/bin/sleep",
						File:          "/usr/bin/sleep",
						DevMajor:      utils.NormalizedInt,
						DevMinor:      utils.NormalizedInt,
						Inode:         utils.NormalizedInt,
						ParentExepath: "/usr/bin/sh2",

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
					{
						CommonData:    utils.BuildCommonData(containerName, commonDataOpts...),
						Proc:          utils.BuildProc("sleep", 1000, 1111),
						Cwd:           "/tmp",
						Args:          strings.Join(sleep2Args, " "),
						PupperLayer:   true,
						UpperLayer:    false,
						FupperLayer:   false,
						Exepath:       "/usr/bin/sleep",
						File:          "/usr/bin/sleep",
						DevMajor:      utils.NormalizedInt,
						DevMinor:      utils.NormalizedInt,
						Inode:         utils.NormalizedInt,
						ParentExepath: "/usr/bin/sh2",

						// Check the existence of the following fields
						Timestamp: utils.NormalizedStr,
						Loginuid:  utils.NormalizedInt,
						Sessionid: utils.NormalizedInt,
					},
				}
				normalize := func(e *traceExecEvent) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeString(&e.Runtime.ContainerID)
					utils.NormalizeString(&e.Timestamp)
					utils.NormalizeProc(&e.Proc)
					utils.NormalizeInt(&e.Loginuid)
					utils.NormalizeInt(&e.Sessionid)
					// Don't use NormalizeInt() because 0 is a valid device major for overlayfs
					e.DevMajor = utils.NormalizedInt
					utils.NormalizeInt(&e.DevMinor)
					utils.NormalizeInt(&e.Inode)

					// We can't know the parent process of the first process inside
					// the container as it depends on the container runtime
					if e.Proc.Comm == "sh" || e.Proc.Parent.Comm == "containerd-shim" {
						utils.NormalizeString(&e.Proc.Parent.Comm)
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
