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

package integration

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

// cpuburnPy is a CPU-bound pure-Python workload. profile_cpu is a perf_event
// gadget: to validate OTel/Python stack symbolization from a perf_event
// program, we need a process that keeps the CPython interpreter busy in
// recognizable Python frames so that the sampler repeatedly lands in them and
// the OTel eBPF profiler can symbolize them (compute_fibonacci / burn_cpu /
// main).
//
// It is written into the container at runtime (see workloadCommand) instead of
// being shipped as a file, so the same workload runs in ig, container and
// Kubernetes modes without depending on the test source tree being reachable
// from the target.
const cpuburnPy = `
import sys
import time

def compute_fibonacci(n):
    if n < 2:
        return n
    return compute_fibonacci(n - 1) + compute_fibonacci(n - 2)

def burn_cpu(deadline):
    total = 0
    while time.time() < deadline:
        total += compute_fibonacci(20)
    return total

def main():
    duration = float(sys.argv[1]) if len(sys.argv) > 1 else 15.0
    burn_cpu(time.time() + duration)

if __name__ == "__main__":
    main()
`

// workloadCommand returns the shell command running the Python workload inside
// the container.
//
// The script is executed directly (not as "python3 cpuburn.py") so that the
// process comm is "cpuburn.py", which the gadget filters on. Its shebang is
// generated at runtime because the official Python images ship the interpreter
// in /usr/local/bin, not /usr/bin.
func workloadCommand() string {
	script := base64.StdEncoding.EncodeToString([]byte(cpuburnPy))
	return fmt.Sprintf("printf '#!%%s\\n' $(command -v python3) > /cpuburn.py && "+
		"echo %s | base64 -d >> /cpuburn.py && "+
		"chmod +x /cpuburn.py && "+
		"while true; do /cpuburn.py 30; done", script)
}

type userStackRaw struct {
	Symbols string `json:"symbols"`
}

type profileCpuEvent struct {
	utils.CommonData

	Proc         utils.Process `json:"proc"`
	Samples      uint64        `json:"samples"`
	UserStackRaw userStackRaw  `json:"user_stack_raw"`
}

// TestProfileCpuOtelStacks verifies OTel eBPF profiler symbolization of Python
// stacks from profile_cpu, which is a perf_event gadget. It exercises the
// perf_event OTel tail-call path (otel_tc_perf / native_tracer_entry).
func TestProfileCpuOtelStacks(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)
	gadgettesting.RequireInitPidNs(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	containerName := "test-profile-cpu-otel-stacks"
	containerImage := gadgettesting.PythonImage

	var ns string
	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(containerImage),
		// The workload is started as a test step, after the gadget has been
		// given time to initialize the OTel eBPF profiler.
		containers.WithStartAndStop(),
	}

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, "test-profile-cpu-otel-stacks")
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(containerName, workloadCommand(), containerOpts...)

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option
	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(containerImage),
	}
	commonFlags := []string{
		"--collect-ustack=true",
		"--symbolizers=otel-ebpf-profiler",
		"--collect-otel-stack=true",
		"--user-stacks-only=true",
		"--comm=cpuburn.py",
	}

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(
			append(commonFlags, fmt.Sprintf("-r=%s", utils.Runtime), fmt.Sprintf("-c=%s", containerName))...))
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts, igrunner.WithFlags(
			append(commonFlags, fmt.Sprintf("-n=%s", ns))...))
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	runnerOpts = append(runnerOpts,
		igrunner.WithStartAndStop(),
		// Like ci/stacks, this is an OTel eBPF profiler gadget: it does not emit
		// the standard "running..." readiness marker in a usable way (the
		// profiler samples over a window and has its own ~tens-of-seconds
		// initialization), so disable the readiness gate and rely on the
		// explicit Sleep before the workload instead.
		igrunner.WithoutReadinessGate(),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			// The container ID is only known once the container has been
			// started, which happens after the gadget: resolve it here.
			dataOpts := make([]utils.CommonDataOption, 0, len(commonDataOpts)+1)
			dataOpts = append(dataOpts, commonDataOpts...)
			dataOpts = append(dataOpts, utils.WithContainerID(testContainer.ID()))

			// Assert that at least one sampled stack contains the full
			// expected pure-Python call chain, proving the perf_event OTel
			// path symbolized Python frames.
			expectedEntries := []*profileCpuEvent{
				{
					CommonData:   utils.BuildCommonData(containerName, dataOpts...),
					Proc:         utils.BuildProc("cpuburn.py", 0, 0),
					UserStackRaw: userStackRaw{Symbols: "python-frames-present"},
				},
			}

			normalize := func(e *profileCpuEvent) {
				utils.NormalizeCommonData(&e.CommonData)
				utils.NormalizeProc(&e.Proc)
				e.Samples = 0

				s := e.UserStackRaw.Symbols
				if strings.Contains(s, "compute_fibonacci") &&
					strings.Contains(s, "burn_cpu") &&
					strings.Contains(s, "main") {
					e.UserStackRaw.Symbols = "python-frames-present"
					return
				}
				e.UserStackRaw.Symbols = ""
			}

			match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntries...)
		}),
	)

	profileCpuCmd := igrunner.New("profile_cpu", runnerOpts...)

	steps := []igtesting.TestStep{
		profileCpuCmd,
		// OTel eBPF profiler needs ~16s to initialize.
		utils.Sleep(20 * time.Second),
		testContainer,
		// Give the profiler time to analyze the Python process and collect
		// symbolized samples from it.
		utils.Sleep(20 * time.Second),
	}
	igtesting.RunTestSteps(steps, t, testingOpts...)
}
