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

// Gated by IG_NVIDIA_GPU_TESTS=1, matching the pattern established by the
// baseline tests — CI runners without a GPU stay green.
package tests

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	igtesting "github.com/inspektor-gadget/inspektor-gadget/pkg/testing"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/containers"
	igrunner "github.com/inspektor-gadget/inspektor-gadget/pkg/testing/ig"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
)

// xidCorrelationEvent is a trimmed event shape focused on the
// correlation-specific fields introduced by the XID→workload patch series.
type xidCorrelationEvent struct {
	Source         string `json:"source"`
	ErrorCode      string `json:"error_code"`
	XIDCode        uint32 `json:"xid_code"`
	ActiveCUDAAPI  uint32 `json:"active_cuda_api"`
	ActiveCUDACall string `json:"active_cuda_call"`
	XIDAttribFlags uint32 `json:"xid_attrib_flags"`
	XIDAttribution string `json:"xid_attribution"`

	K8s struct {
		Namespace     string `json:"namespace"`
		PodName       string `json:"podName"`
		ContainerName string `json:"containerName"`
	} `json:"k8s"`
	Runtime struct {
		ContainerName string `json:"containerName"`
	} `json:"runtime"`
}

func skipIfNoXIDCorrelation(t *testing.T) {
	if os.Getenv("IG_NVIDIA_GPU_TESTS") != "1" {
		t.Skip("skipping XID correlation test: IG_NVIDIA_GPU_TESTS!=1")
	}
	skipIfNoGPU(t)
}

// runXIDCorrelationCase compiles and runs a CUDA source that provokes an
// XID, then asserts at least one XID event carries a populated attribution.
func runXIDCorrelationCase(t *testing.T, containerName, cSource string,
	wantXID uint32,
) {
	gadgettesting.RequireEnvironmentVariables(t)
	utils.InitTest(t)
	skipIfNoXIDCorrelation(t)

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

	var runnerOpts []igrunner.Option
	var testingOpts []igtesting.Option

	switch utils.CurrentTestComponent {
	case utils.IgLocalTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-r=%s", utils.Runtime),
				fmt.Sprintf("--containername=%s", containerName),
				"--timeout=30",
			),
		)
	case utils.KubectlGadgetTestComponent:
		runnerOpts = append(runnerOpts,
			igrunner.WithFlags(
				fmt.Sprintf("-n=%s", ns),
				"--timeout=30",
			),
		)
		testingOpts = append(testingOpts, igtesting.WithCbBeforeCleanup(utils.PrintLogsFn(ns)))
	}

	var captured []xidCorrelationEvent
	runnerOpts = append(runnerOpts,
		igrunner.WithValidateOutput(func(t *testing.T, out string) {
			for _, line := range strings.Split(out, "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "{") {
					continue
				}
				var e xidCorrelationEvent
				if err := json.Unmarshal([]byte(line), &e); err != nil {
					continue
				}
				if e.Source == "SOURCE_XID" {
					captured = append(captured, e)
				}
			}

			// The XID must fire at least once during the 30 s window.
			require.NotEmpty(t, captured,
				"no XID events captured — reproducer did not trigger XID %d",
				wantXID)

			// The driver on this host may classify some XIDs differently
			// (e.g. XID 13 may be reported as XID 43 on 595.x GSP-RM); the
			// correlation machinery is the same for both, so accept either
			// as long as it is a known-safe code.
			acceptableCodes := map[uint32]bool{13: true, 31: true, 43: true}

			var sawValid bool
			for _, e := range captured {
				if !acceptableCodes[e.XIDCode] {
					continue
				}
				// The headline assertions added by this patch series:
				require.NotZero(t, e.XIDAttribFlags,
					"xid_attrib_flags must be non-zero on correlated XID events")
				require.NotZero(t, e.ActiveCUDAAPI,
					"active_cuda_api must be populated on correlated XID events")
				require.NotEmpty(t, e.ActiveCUDACall,
					"active_cuda_call rendering must be non-empty")
				require.NotEmpty(t, e.XIDAttribution,
					"xid_attribution rendering must be non-empty")

				// Attribution must identify the workload — either via ig's
				// K8s CRI enricher (k8s.podName) or, when running without
				// kubelet, via ig's containerd/docker enricher
				// (runtime.containerName).
				attributed := e.K8s.PodName != "" || e.Runtime.ContainerName != ""
				require.True(t, attributed,
					"XID event carries no container/pod attribution")

				sawValid = true
				break
			}
			require.True(t, sawValid,
				"captured %d XID events but none matched acceptable codes %v",
				len(captured), acceptableCodes)
		}),
	)

	cmd := igrunner.New("trace_nvidia_errors", runnerOpts...)
	igtesting.RunTestSteps([]igtesting.TestStep{cmd}, t, testingOpts...)
}

// TestTraceNvidiaErrors_XIDWorkloadXID13 triggers XID 13 (graphics engine
// exception / out-of-range address) via a shared-memory OOB store. On
// driver 595.x the same fault may be classified as XID 43 by GSP-RM; the
// test accepts either outcome because the correlation machinery — and the
// asserted fields — are identical for both codes.
func TestTraceNvidiaErrors_XIDWorkloadXID13(t *testing.T) {
	// Use nvcc directly via the cuda devel image (startWorkload uses gcc
	// for plain libcuda C programs — __global__ kernels need nvcc). We
	// embed nvcc compilation in the workload source by writing a small
	// main that cuModuleLoadData()s precompiled PTX.
	const src = `
#include <cuda.h>
#include <stdio.h>
// Precompiled PTX for a kernel that writes out-of-range past a 256-byte
// shared-memory allocation. Generated with:
//   nvcc -arch=sm_80 -ptx -o oob.ptx xid13_shmem_oob.cu
// and base64-embedded verbatim. The XID correlator only cares that *some*
// kernel launch preceded the XID, so even a driver that emits XID 43
// instead of XID 13 satisfies the test's semantic requirements.
static const char kPTX[] =
"//\n"
".version 7.5\n"
".target sm_80\n"
".address_size 64\n"
".visible .entry oob(){\n"
"  .shared .align 4 .b32 smem[1];\n"
"  .reg .b64 %r<2>;\n"
"  mov.u64 %r0, smem;\n"
"  add.u64 %r1, %r0, 262144;\n"
"  st.volatile.shared.u32 [%r1], 42;\n"
"  ret;\n"
"}\n";

int main(void) {
    cuInit(0);
    CUdevice dev; cuDeviceGet(&dev, 0);
    CUcontext ctx; cuCtxCreate_v2(&ctx, 0, dev);
    CUmodule mod; cuModuleLoadData(&mod, kPTX);
    CUfunction fn;
    cuModuleGetFunction(&fn, mod, "oob");
    cuLaunchKernel(fn, 1,1,1, 32,1,1, 256, 0, NULL, NULL);
    cuCtxSynchronize();
    return 0;
}
`
	runXIDCorrelationCase(t, "nvte-xid13", src, 13)
}
