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
	"encoding/base64"
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

type traceDeadlockEvent struct {
	eventtypes.CommonData
	Comm     string `json:"comm"`
	PID      uint32 `json:"pid"`
	Nodes    uint64 `json:"nodes"`
	Stackids string `json:"stack_ids"`
}

func TestDeadlock(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	containerName := "test-deadlock"
	containerImage := "gcc:latest"

	var ns string
	containerOpts := []containers.ContainerOption{containers.WithContainerImage(containerImage)}

	switch utils.CurrentTestComponent {
	case utils.KubectlGadgetTestComponent:
		ns = utils.GenerateTestNamespaceName(t, "test-deadlock")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	execProgram := `
#include <iostream>
#include <mutex>
#include <thread>

std::mutex global_mutex1;
std::mutex global_mutex2;

  int main(void) {
    static std::mutex static_mutex3;
    std::mutex local_mutex4;

    std::this_thread::sleep_for(std::chrono::seconds(10));

    auto t1 = std::thread([] {
      std::lock_guard<std::mutex> g1(global_mutex1);
      std::lock_guard<std::mutex> g2(global_mutex2);
    });
    t1.join();

    auto t2 = std::thread([] {
      std::lock_guard<std::mutex> g2(global_mutex2);
      std::lock_guard<std::mutex> g3(static_mutex3);
    });
    t2.join();

    auto t3 = std::thread([&local_mutex4] {
      std::lock_guard<std::mutex> g3(static_mutex3);
      std::lock_guard<std::mutex> g4(local_mutex4);
    });
    t3.join();

    auto t4 = std::thread([&local_mutex4] {
      std::lock_guard<std::mutex> g4(local_mutex4);
      std::lock_guard<std::mutex> g1(global_mutex1);
    });
    t4.join();

    std::this_thread::sleep_for(std::chrono::seconds(5));
  }
`
	progBase64 := base64.StdEncoding.EncodeToString([]byte(execProgram))

	testContainer := containerFactory.NewContainer(
		containerName,
		fmt.Sprintf("echo %s | base64 -d  > program.cpp && g++ -std=c++17 -o program program.cpp && ./program", progBase64),
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
		utils.WithContainerID(testContainer.ID()),
	}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-r=%s", utils.Runtime), "--timeout=30"))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(fmt.Sprintf("-n=%s", ns), "--timeout=30"))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts, igrunner.WithValidateOutput(
		func(t *testing.T, output string) {
			expectedEntry := &traceDeadlockEvent{
				CommonData: utils.BuildCommonData(containerName, commonDataOpts...),
				Nodes:      4,
				Comm:       "program",
				PID:        utils.NormalizedInt,
				Stackids:   utils.NormalizedStr,
			}

			normalize := func(e *traceDeadlockEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeInt(&e.PID)
				utils.NormalizeString(&e.Stackids)
			}

			match.MatchEntries(t, match.JSONMultiObjectMode, output, normalize, expectedEntry)
		},
	))

	deadlockCmd := igrunner.New("deadlock", runnerOpts...)

	igtesting.RunTestSteps([]igtesting.TestStep{deadlockCmd}, t, testingOpts...)
}
