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
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
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

	runtime := os.Getenv("IG_RUNTIME")

	containerRuntime := runtime

	if runtime == "kubernetes" {
		// Get container runtime used in the cluster
		containerRuntime = gadgettesting.GetContainerRuntime(t)
	}

	var expectedCommonData eventtypes.CommonData
	var ns string
	var opts []igrunner.Option
	var isDockerRuntime bool

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

	switch match.DefaultTestComponent {
	default:
		t.Fatalf("TODO: invalid thing")
	case match.IgTestComponent:
		opts = append(opts, igrunner.WithFlags(fmt.Sprintf("-r %s", containerRuntime), "--timeout=5"))

		expectedCommonData = eventtypes.CommonData{
			Runtime: eventtypes.BasicRuntimeMetadata{
				RuntimeName:        eventtypes.String2RuntimeName(containerRuntime),
				ContainerName:      containerName,
				ContainerID:        testContainer.ID(),
				ContainerImageName: containerImage,
			},
		}
	case match.InspektorGadgetTestComponent:
		isDockerRuntime = containerRuntime == "docker"
		//ns = k8s.GenerateTestNamespaceName("test-trace-open")
		// TODO: allow passing this to the runtime
		ns = "myfoonamespace"

		opts = append(opts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns)))
		opts = append(opts, igrunner.WithStartAndStop())

		expectedCommonData = match.BuildCommonData(ns,
			match.WithContainerImageName("docker.io/library/busybox:latest",
				isDockerRuntime,
			))

		// TODO: This should be another option passed to BuildCommonData
		expectedCommonData.K8s.ContainerName = containerName
		expectedCommonData.K8s.PodName = containerName
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

	traceOpenCmd := igrunner.New("trace_open", opts...)

	igtesting.RunTestSteps([]igtesting.TestStep{traceOpenCmd}, t)
}
