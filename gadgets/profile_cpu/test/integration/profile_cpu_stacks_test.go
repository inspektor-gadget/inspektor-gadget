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
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// findWorkloadDir locates the profile_cpu/workload directory relative to this
// test file's source location.
func findWorkloadDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "cannot determine test file path")
	// This file is at gadgets/profile_cpu/test/integration/profile_cpu_stacks_test.go
	// Workload is at gadgets/profile_cpu/workload/
	return filepath.Join(filepath.Dir(filename), "..", "..", "workload")
}

type userStackRaw struct {
	Symbols string `json:"symbols"`
}

type profileCpuEvent struct {
	Proc         utils.Process `json:"proc"`
	Samples      uint64        `json:"samples"`
	UserStackRaw userStackRaw  `json:"user_stack_raw"`
}

// workloadStep runs the CPU-bound Python workload as a local process. It burns
// CPU (in recognizable pure-Python frames) for the given duration so that the
// perf_event sampler + OTel eBPF profiler can capture and symbolize the frames.
type workloadStep struct {
	workDir  string
	duration string
}

func (w *workloadStep) Run(t *testing.T) {
	t.Helper()
	cmd := exec.Command("./cpuburn.py", w.duration)
	cmd.Dir = w.workDir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "running Python workload: %s", string(out))
}

func (w *workloadStep) Start(t *testing.T)   { t.Helper(); w.Run(t) }
func (w *workloadStep) Stop(t *testing.T)    {}
func (w *workloadStep) IsStartAndStop() bool { return false }
func (w *workloadStep) Running() bool        { return false }

// TestProfileCpuOtelStacks verifies OTel eBPF profiler symbolization of Python
// stacks from profile_cpu, which is a perf_event gadget. It exercises the
// perf_event OTel tail-call path (otel_tc_perf / native_tracer_entry).
//
// TODO(#5703): Like ci/stacks, this test only runs in --host mode with a local
// Python workload. Once the python:3.13-slim image is mirrored to
// ghcr.io/inspektor-gadget/ci/python (inspektor-gadget/inspektor-gadget#5703),
// switch to running the workload in a container and drop the
// IgLocalTestComponent skip so it also runs in container/Kubernetes mode.
func TestProfileCpuOtelStacks(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("profile_cpu OTel stacks test only supports ig local mode (requires --host)")
	}

	workloadSrcDir := findWorkloadDir(t)

	// Burn CPU long enough for the OTel profiler to analyze the process and
	// collect symbolized samples after it starts (the gadget step waits for
	// the profiler to initialize before the workload runs).
	workload := &workloadStep{workDir: workloadSrcDir, duration: "20"}

	var runnerOpts []igrunner.Option

	runnerOpts = append(runnerOpts,
		igrunner.WithFlags(
			"--host",
			"--collect-ustack=true",
			"--symbolizers=otel-ebpf-profiler",
			"--collect-otel-stack=true",
			"--user-stacks-only=true",
			"--comm=cpuburn.py",
		),
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			// Assert that at least one sampled stack contains the full
			// expected pure-Python call chain, proving the perf_event OTel
			// path symbolized Python frames.
			expectedEntries := []*profileCpuEvent{
				{
					Proc:         utils.BuildProc("cpuburn.py", 0, 0),
					UserStackRaw: userStackRaw{Symbols: "python-frames-present"},
				},
			}

			normalize := func(e *profileCpuEvent) {
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
		workload,
	}
	igtesting.RunTestSteps(steps, t)
}
