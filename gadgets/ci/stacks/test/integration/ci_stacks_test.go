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

// findWorkloadDir locates the ci/stacks/workload directory
// relative to this test file's source location.
func findWorkloadDir(t *testing.T) string {
	t.Helper()
	_, filename, _, ok := runtime.Caller(0)
	require.True(t, ok, "cannot determine test file path")
	// This file is at gadgets/ci/stacks/test/integration/ci_stacks_test.go
	// Workload is at gadgets/ci/stacks/workload/
	return filepath.Join(filepath.Dir(filename), "..", "..", "workload")
}

type ustackRaw struct {
	Symbols string `json:"symbols"`
}

type stacksEvent struct {
	Proc      utils.Process `json:"proc"`
	Count     uint64        `json:"count"`
	UstackRaw ustackRaw     `json:"ustack_raw"`
}

// workloadStep runs the Python workload as a local process.
type workloadStep struct {
	workDir string
}

func (w *workloadStep) Run(t *testing.T) {
	t.Helper()
	cmd := exec.Command("./pydemo.py")
	cmd.Dir = w.workDir
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "running Python workload: %s", string(out))
}

func (w *workloadStep) Start(t *testing.T)   { t.Helper(); w.Run(t) }
func (w *workloadStep) Stop(t *testing.T)    {}
func (w *workloadStep) IsStartAndStop() bool { return false }
func (w *workloadStep) Running() bool        { return false }

// TestCiStacks tests OTel eBPF profiler symbolization of Python stacks.
//
// TODO: This test only runs in --host mode with a local Python workload.
// It does not yet work in Kubernetes container mode because:
// - The ci/stacks gadget attaches uprobes to libmylib.so at a well-known
//   host path (/tmp/ig-tests/ci-stacks-workload/libmylib.so). The uprobe
//   is installed at container-start time, so the library must exist on
//   disk before the container starts. Compiling the library inside the
//   container (like trace_capabilities does with its C workload) would
//   not work because the uprobe would miss the library.
// - A Python container image would be needed in the CI test images.
func TestCiStacks(t *testing.T) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)

	if utils.CurrentTestComponent != utils.IgLocalTestComponent {
		t.Skip("ci/stacks test only supports ig local mode (requires --host)")
	}

	// Ensure workload is built and installed.
	workloadSrcDir := findWorkloadDir(t)
	installCmd := exec.Command("make", "install")
	installCmd.Dir = workloadSrcDir
	out, err := installCmd.CombinedOutput()
	require.NoError(t, err, "building workload: %s", string(out))

	workload := &workloadStep{workDir: workloadSrcDir}

	var runnerOpts []igrunner.Option

	runnerOpts = append(runnerOpts,
		igrunner.WithFlags(
			"--host",
			"--collect-ustack=true",
			"--symbolizers=otel-ebpf-profiler",
			"--collect-otel-stack=true",
			"--comm=pydemo.py",
			"--verify-image=false",
		),
		igrunner.WithStartAndStop(),
		igrunner.WithValidateOutput(func(t *testing.T, output string) {
			expectedEntries := []*stacksEvent{
				{
					Proc:      utils.BuildProc("pydemo.py", 0, 0),
					UstackRaw: ustackRaw{Symbols: "eat_apple"},
				},
				{
					Proc:      utils.BuildProc("pydemo.py", 0, 0),
					UstackRaw: ustackRaw{Symbols: "eat_banana"},
				},
				{
					Proc:      utils.BuildProc("pydemo.py", 0, 0),
					UstackRaw: ustackRaw{Symbols: "eat_orange"},
				},
			}

			normalize := func(e *stacksEvent) {
				utils.NormalizeProc(&e.Proc)
				e.Count = 0

				for _, fn := range []string{"eat_apple", "eat_banana", "eat_orange"} {
					if strings.Contains(e.UstackRaw.Symbols, fn) {
						e.UstackRaw.Symbols = fn
						return
					}
				}
				e.UstackRaw.Symbols = ""
			}

			match.MatchEntries(t, match.JSONMultiArrayMode, output, normalize, expectedEntries...)
		}),
	)

	stacksCmd := igrunner.New("ci/stacks", runnerOpts...)

	steps := []igtesting.TestStep{
		stacksCmd,
		// OTel eBPF profiler needs ~16s to initialize.
		utils.Sleep(20 * time.Second),
		workload,
	}
	igtesting.RunTestSteps(steps, t)
}
