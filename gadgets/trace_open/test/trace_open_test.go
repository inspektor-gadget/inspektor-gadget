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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/k8s"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type traceOpenEvent struct {
	eventtypes.CommonData

	MountNsID uint64 `json:"mountnsid"`
	Pid       uint32 `json:"pid"`
	Uid       uint32 `json:"uid"`
	Gid       uint32 `json:"gid"`
	Comm      string `json:"comm"`
	Fd        uint32 `json:"fd"`
	Err       int32  `json:"err"`
	Ret       int    `json:"ret"`
	Flags     int    `json:"flags"`
	Mode      int    `json:"mode"`
	FName     string `json:"fname"`
}

func TestTraceOpen(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	match.SetDefaultTestComponent()

	runtime := "docker"

	var expectedCommonData eventtypes.CommonData
	var ns string
	var opts []igrunner.Option
	var isDockerRuntime bool

	switch match.DefaultTestComponent {
	case match.IgTestComponent:
		opts = append(opts, igrunner.WithFlags(fmt.Sprintf("-r %s", runtime), "--timeout=5"))

		containerFactory, err := containers.NewContainerFactory(runtime)
		require.NoError(t, err, "new container factory")
		containerName := "test-trace-open"
		containerImage := "docker.io/library/busybox"

		testContainer := containerFactory.NewContainer(
			containerName,
			"while true; do setuidgid 1000:1111 cat /dev/null; sleep 0.1; done",
			containers.WithContainerImage(containerImage),
		)

		testContainer.Start(t)
		t.Cleanup(func() {
			testContainer.Stop(t)
		})

		expectedCommonData = eventtypes.CommonData{
			Runtime: eventtypes.BasicRuntimeMetadata{
				RuntimeName:        eventtypes.String2RuntimeName(runtime),
				ContainerName:      containerName,
				ContainerID:        testContainer.ID(),
				ContainerImageName: containerImage,
			},
		}
	case match.InspektorGadgetTestComponent:
		isDockerRuntime = runtime == "docker"
		ns = k8s.GenerateTestNamespaceName("test-trace-open")

		opts = append(opts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		opts = append(opts, igrunner.WithStartAndStop())

		expectedCommonData = match.BuildCommonData(ns, match.WithContainerImageName("docker.io/library/busybox:latest", isDockerRuntime))
	}

	opts = append(opts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceOpenEvent{
				CommonData: expectedCommonData,
				Comm:       "cat",
				FName:      "/dev/null",
				Fd:         3,
				Err:        0,
				Uid:        1000,
				Gid:        1111,
				Flags:      0,
				Mode:       0,
			}

			normalize := func(e *traceOpenEvent) {
				e.MountNsID = 0
				e.Pid = 0

				// The container image digest is not currently enriched for Docker containers:
				// https://github.com/inspektor-gadget/inspektor-gadget/issues/2365
				if e.Runtime.RuntimeName == eventtypes.RuntimeNameDocker {
					e.Runtime.ContainerImageDigest = ""
				}

				match.NormalizeCommonData(&e.CommonData, ns)
			}

			match.ExpectEntriesToMatch(t, output, normalize, expectedEntry)
		},
	))

	traceOpenCmd := igrunner.New(
		"trace_open",
		opts...,
	)

	switch match.DefaultTestComponent {
	case match.IgTestComponent:
		igtesting.RunTestSteps([]igtesting.TestStep{traceOpenCmd}, t)
	case match.InspektorGadgetTestComponent:
		igtesting.RunTestSteps([]igtesting.TestStep{
			k8s.CreateTestNamespaceCommand(ns),
			traceOpenCmd,
			k8s.SleepForSecondsCommand(2), // wait to ensure kubectl-gadget has started
			k8s.BusyboxPodRepeatCommand(t, ns, "setuidgid 1000:1111 cat /dev/null"),
			k8s.WaitUntilTestPodReadyCommand(t, ns),
			k8s.DeleteTestNamespaceCommand(t, ns),
		}, t, igtesting.WithCbBeforeCleanup(k8s.PrintLogsFn(ns)))
	}
}
