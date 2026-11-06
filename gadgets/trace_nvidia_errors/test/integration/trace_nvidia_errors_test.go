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

// Package tests is the integration-test suite for the trace_nvidia_errors
// gadget. It follows the Inspektor Gadget convention of a single *_test.go
// file in test/integration/, driven via `make trace_nvidia_errors/test-integration`.
package tests

import (
	"encoding/base64"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/match"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// cudaImage has gcc + the libcuda headers/stub; the NVIDIA container runtime
// replaces the stub libcuda.so.1 with the real driver library at run time.
const cudaImage = "nvidia/cuda:12.3.2-devel-ubuntu22.04"

// traceNvidiaErrorEvent is the JSON shape emitted by the gadget after WASM
// enrichment.
type traceNvidiaErrorEvent struct {
	utils.CommonData

	Timestamp string        `json:"timestamp"`
	Proc      utils.Process `json:"proc"`

	Source      string `json:"source"`
	ErrorCode   string `json:"error_code"`
	APIID       string `json:"api_id"`
	XIDCode     uint32 `json:"xid_code"`
	Severity    string `json:"severity"`
	Category    string `json:"category"`
	Description string `json:"description"`
	Why         string `json:"why"`
	Suggestion  string `json:"suggestion"`
	ContextInfo string `json:"context_info"`
}

// skipIfNoGPU skips the test when IG_NVIDIA_GPU_TESTS is not set. This
// protects CI runners without GPUs from attempting to run these tests.
func skipIfNoGPU(t *testing.T) {
	if os.Getenv("IG_NVIDIA_GPU_TESTS") != "1" {
		t.Skip("skipping: IG_NVIDIA_GPU_TESTS!=1")
	}
}

// buildWorkloadCmd returns a shell command that compiles and loops a CUDA C
// source snippet inside the container.
func buildWorkloadCmd(cSource string) string {
	enc := base64.StdEncoding.EncodeToString([]byte(cSource))
	return fmt.Sprintf(
		`echo %s | base64 -d > /tmp/t.c && `+
			`gcc -I/usr/local/cuda/include -o /tmp/t /tmp/t.c -lcuda && `+
			`while true; do /tmp/t >/dev/null 2>&1; sleep 1; done`,
		enc,
	)
}

// runCase starts the workload via the container framework, runs the gadget
// with --timeout=15 against that container, and asserts at least one event
// matches expect.
func runCase(t *testing.T, containerName, cSource string,
	expect *traceNvidiaErrorEvent,
) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)
	skipIfNoGPU(t)

	containerFactory, err := containers.NewContainerFactory(utils.Runtime)
	require.NoError(t, err, "new container factory")

	containerOpts := []containers.ContainerOption{
		containers.WithContainerImage(cudaImage),
		containers.WithGPUs(),
	}

	var ns string
	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		ns = utils.GenerateTestNamespaceName(t, containerName)
		containerOpts = append(containerOpts, containers.WithContainerNamespace(ns))
	}

	testContainer := containerFactory.NewContainer(
		containerName,
		buildWorkloadCmd(cSource),
		containerOpts...,
	)

	testContainer.Start(t)
	t.Cleanup(func() {
		testContainer.Stop(t)
	})

	commonDataOpts := []utils.CommonDataOption{
		utils.WithContainerImageName(utils.NormalizedStr),
		utils.WithContainerID(utils.NormalizedStr),
	}

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				fmt.Sprintf("--containername=%s", containerName),
				"--timeout=15",
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-n=%s", ns),
				"--timeout=15",
			),
		)
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
		commonDataOpts = append(commonDataOpts, utils.WithK8sNamespace(ns))
	}

	expect.CommonData = utils.BuildCommonData(containerName, commonDataOpts...)

	runnerOpts = append(runnerOpts,
		igrunner.WithValidateOutput(
			func(t *testing.T, output string) {
				normalize := func(e *traceNvidiaErrorEvent) {
					utils.NormalizeCommonData(&e.CommonData)
					utils.NormalizeString(&e.Runtime.ContainerID)
					utils.NormalizeString(&e.Runtime.ContainerImageName)
					utils.NormalizeString(&e.Timestamp)
					utils.NormalizeProc(&e.Proc)
					utils.NormalizeString(&e.Description)
					utils.NormalizeString(&e.Why)
					utils.NormalizeString(&e.Suggestion)
					utils.NormalizeString(&e.ContextInfo)
					utils.NormalizeString(&e.APIID)
					e.XIDCode = 0
				}
				match.MatchEntries(t, match.JSONMultiObjectMode, output,
					normalize, expect)
			},
		),
	)

	cmd := igrunner.New("trace_nvidia_errors", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t, testingOpts...)
}

// TestTraceNvidiaErrors_InvalidDevice triggers CUDA_ERROR_INVALID_DEVICE via
// cuCtxCreate_v2 with an ordinal far outside [0, N).
func TestTraceNvidiaErrors_InvalidDevice(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, 9999);
    return 0;
}
`
	runCase(t, "nvte-invdev", src,
		&traceNvidiaErrorEvent{
			Source:      "SOURCE_CUDA_API",
			ErrorCode:   "CUDA_ERROR_INVALID_DEVICE",
			Severity:    "MEDIUM",
			Category:    "device",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}

// TestTraceNvidiaErrors_OOM triggers CUDA_ERROR_OUT_OF_MEMORY via a 256 GiB
// cuMemAlloc_v2 request.
func TestTraceNvidiaErrors_OOM(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUdevice dev;
    cuDeviceGet(&dev, 0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, dev);
    CUdeviceptr p;
    cuMemAlloc_v2(&p, 256ULL * 1024 * 1024 * 1024);
    return 0;
}
`
	runCase(t, "nvte-oom", src,
		&traceNvidiaErrorEvent{
			Source:      "SOURCE_CUDA_API",
			ErrorCode:   "CUDA_ERROR_OUT_OF_MEMORY",
			Severity:    "HIGH",
			Category:    "memory",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}

// TestTraceNvidiaErrors_InvalidImage triggers CUDA_ERROR_INVALID_IMAGE by passing
// a non-PTX blob to cuModuleLoadData (driver reports INVALID_IMAGE before
// reaching the PTX JIT path when the blob is plainly malformed).
func TestTraceNvidiaErrors_InvalidImage(t *testing.T) {
	const src = `
#include <cuda.h>
int main(void) {
    cuInit(0);
    CUdevice dev;
    cuDeviceGet(&dev, 0);
    CUcontext ctx;
    cuCtxCreate_v2(&ctx, 0, dev);
    CUmodule m;
    const char *bad = "THIS IS NOT PTX";
    cuModuleLoadData(&m, bad);
    return 0;
}
`
	runCase(t, "nvte-badptx", src,
		&traceNvidiaErrorEvent{
			Source:      "SOURCE_CUDA_API",
			ErrorCode:   "CUDA_ERROR_INVALID_IMAGE",
			Severity:    "MEDIUM",
			Category:    "compilation",
			APIID:       utils.NormalizedStr,
			Description: utils.NormalizedStr,
			Why:         utils.NormalizedStr,
			Suggestion:  utils.NormalizedStr,
			ContextInfo: utils.NormalizedStr,
			Proc:        utils.BuildProc("t", 0, 0),
			Timestamp:   utils.NormalizedStr,
		})
}
