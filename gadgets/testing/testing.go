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

package testing

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/internal/testing/kernel"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	K8sDistroAKSAzureLinux  = "aks-AzureLinux"
	K8sDistroAKSUbuntu      = "aks-Ubuntu"
	K8sDistroARO            = "aro"
	K8sDistroMinikubeGH     = "minikube-github"
	K8sDistroEKSAmazonLinux = "eks-AmazonLinux"
	K8sDistroGKECOS         = "gke-COS_containerd"
)

const (
	BusyBoxImage          = "ghcr.io/inspektor-gadget/ci/busybox:latest"
	NginxImage            = "ghcr.io/inspektor-gadget/ci/nginx:latest"
	GccImage              = "ghcr.io/inspektor-gadget/ci/gcc:latest"
	NetworkMultitoolImage = "ghcr.io/inspektor-gadget/ci/network-multitool:latest"
	RegistryImage         = "ghcr.io/inspektor-gadget/ci/registry:2"
	// PythonImage is pinned to 3.13 (not the floating "3" tag) because the OTel
	// eBPF profiler only symbolizes CPython up to 3.14. See the same pin in
	// .github/workflows/dockerhub-mirror.yml.
	PythonImage = "ghcr.io/inspektor-gadget/ci/python:3.13-slim"
)

func SkipK8sDistros(t testing.TB, distros ...string) {
	t.Helper()

	k8sDistro := os.Getenv("KUBERNETES_DISTRIBUTION")

	for _, distro := range distros {
		if k8sDistro == distro {
			t.Skipf("Skipping test on Kubernetes distribution %s", distro)
		}
	}
}

func RequireEnvironmentVariables(t testing.TB) {
	if os.Getenv("IG_PATH") == "" {
		t.Skip("environment variable IG_PATH undefined")
	}

	if os.Getenv("IG_RUNTIME") == "" {
		t.Skip("environment variable IG_RUNTIME undefined")
	}
}

// RequireGpuEbpfBridge is called by tests that spawn a gpu-ebpf-bridge
// subprocess (currently only gadgets/ci/gpu). It resolves the bridge
// binary named by the GPU_EBPF_BRIDGE_PATH environment variable (the
// analogue of IG_PATH for the bridge binary: gadgets/Makefile sets it
// from GPU_EBPF_BRIDGE via the test-local target-specific override) and
// returns its path.
//
// A bare name with no path separator (the Makefile default,
// GPU_EBPF_BRIDGE ?= gpu-ebpf-bridge) is looked up on $PATH; an
// explicit path is used verbatim. The test is skipped -- not failed --
// when the variable is empty or the binary cannot be found, so
// environments that do not build the bridge (e.g. the default CI
// gadget-test job) skip cleanly instead of failing.
//
// Kept separate from RequireEnvironmentVariables because most gadget
// tests do not need the bridge and should not skip when it is
// unavailable.
func RequireGpuEbpfBridge(t testing.TB) string {
	t.Helper()
	bridge := os.Getenv("GPU_EBPF_BRIDGE_PATH")
	if bridge == "" {
		t.Skip("environment variable GPU_EBPF_BRIDGE_PATH undefined; the caller must build cmd/gpu-ebpf-bridge and set GPU_EBPF_BRIDGE_PATH")
	}
	// A bare name (no path separator) is resolved via $PATH, matching
	// the Makefile default; an explicit path is used as-is.
	if !strings.ContainsRune(bridge, os.PathSeparator) {
		resolved, err := exec.LookPath(bridge)
		if err != nil {
			t.Skipf("gpu-ebpf-bridge %q not found on $PATH: %v; build cmd/gpu-ebpf-bridge and set GPU_EBPF_BRIDGE_PATH to run this test", bridge, err)
		}
		bridge = resolved
	}
	if _, err := os.Stat(bridge); err != nil {
		t.Skipf("gpu-ebpf-bridge binary %q not available: %v", bridge, err)
	}
	return bridge
}

// RequireInitPidNs skips the test when Inspektor Gadget does not run in the
// initial PID namespace.
//
// The OTel eBPF profiler symbolizer resolves the PIDs reported by eBPF
// programs, which are relative to the initial PID namespace, through its own
// /proc. When Inspektor Gadget runs elsewhere, it finds no process and
// symbolizes nothing. This is the case in Kubernetes, where the gadget
// DaemonSet runs with hostPID: false, and on minikube with the docker driver,
// where even the node itself is in a nested PID namespace.
//
// Note that this is about the PID namespace of Inspektor Gadget itself: the
// traced workloads can be in any PID namespace.
func RequireInitPidNs(t testing.TB) {
	t.Helper()

	if utils.CurrentTestComponent != utils.KubectlGadgetTestComponent {
		// ig is executed by this test, so it shares its PID namespace.
		initPidNs, err := host.IsInitPidNs()
		require.NoError(t, err, "checking if running in the initial PID namespace")
		if !initPidNs {
			t.Skip("Skipping test because ig does not run in the initial PID namespace")
		}
		return
	}

	// ig runs in the gadget pod, whose image is distroless: ask it instead of
	// executing anything in the container.
	path := os.Getenv("IG_PATH")
	if path == "" {
		path = "kubectl-gadget"
	}
	var stderr bytes.Buffer
	cmd := exec.Command(path, "version", "--details", "-o", "json")
	cmd.Stderr = &stderr
	output, err := cmd.Output()
	require.NoError(t, err, "getting gadget service info: %s", stderr.String())

	var info struct {
		ServerPidNamespace *struct {
			IsInit *bool `json:"isInit"`
		} `json:"serverPidNamespace"`
	}
	require.NoError(t, json.Unmarshal(output, &info), "parsing %q", output)

	if info.ServerPidNamespace == nil || info.ServerPidNamespace.IsInit == nil {
		t.Skip("Skipping test because the PID namespace of the gadget service could not be determined")
	}
	if !*info.ServerPidNamespace.IsInit {
		t.Skip("Skipping test because the gadget service does not run in the initial PID namespace")
	}
}

func RemoveMemlock(t testing.TB) {
	t.Helper()
	// Some kernel versions need to have the memlock rlimit removed
	err := rlimit.RemoveMemlock()
	require.NoError(t, err, "Failed to remove memlock rlimit: %s", err)
}

// GetArch returns the architecture of the current node.
// When used in Kubernetes, it gets the architecture from a random node in the cluster.
func GetArch(t testing.TB) string {
	t.Helper()

	var currArch string

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		cmd := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.architecture}")
		output, err := cmd.Output()
		require.NoError(t, err, "Failed to get architecture: %s", err)
		currArch = string(output)
	} else {
		currArch = runtime.GOARCH
	}

	return currArch
}

// GetKernelVersion returns the kernel version of the current node.
// When used in Kubernetes, it gets the kernel version from a random node in the cluster.
func GetKernelVersion(t testing.TB) *kernel.VersionInfo {
	t.Helper()

	var err error
	var currVersion *kernel.VersionInfo

	if utils.CurrentTestComponent == utils.KubectlGadgetTestComponent {
		cmd := exec.Command("kubectl", "get", "nodes", "-o", "jsonpath={.items[0].status.nodeInfo.kernelVersion}")
		output, err := cmd.Output()
		require.NoError(t, err, "Failed to get kernel version: %s", err)
		currVersion, err = kernel.ParseRelease(string(output))
		require.NoError(t, err, "Failed to parse kernel version: %s", err)
	} else {
		currVersion, err = kernel.GetKernelVersion()
		require.NoError(t, err, "Failed to get kernel version: %s", err)
	}

	return currVersion
}

// CheckMinimumKernelVersion returns true if the current kernel version is
// less than minKernelVersion. When used in Kubernetes, it gets the kernel
// version from a random node in the cluster.
func CheckMinimumKernelVersion(t testing.TB, minKernelVersion string) bool {
	t.Helper()

	currVersion := GetKernelVersion(t)

	minVersion, err := kernel.ParseRelease(minKernelVersion)
	require.NoError(t, err, "Failed to parse minKernelVersion: %s", err)

	return kernel.CompareKernelVersion(*currVersion, *minVersion) < 0
}

// MinimumKernelVersion skips the test if the current kernel version is less
// than minKernelVersion. When used in Kubernetes, it gets the kernel version
// from a random node in the cluster.
func MinimumKernelVersion(t testing.TB, minKernelVersion string) {
	t.Helper()

	if CheckMinimumKernelVersion(t, minKernelVersion) {
		t.Skipf("Skipping test because kernel version %s is less than %s",
			GetKernelVersion(t), minKernelVersion)
	}
}

func InitUnitTest(t testing.TB) {
	utils.RequireRoot(t)
	RemoveMemlock(t)
}

type dummyGadgetOpts struct {
	paramValues map[string]string
}

type DummyGadgetOpt func(d *dummyGadgetOpts)

func WithParamValues(paramValues map[string]string) DummyGadgetOpt {
	return func(d *dummyGadgetOpts) {
		d.paramValues = paramValues
	}
}

// DummyGadgetTest runs a dummy gadget test that only checks if the gadget
// can be started without errors.
func DummyGadgetTest(t *testing.T, gadgetName string, optsF ...DummyGadgetOpt) {
	t.Helper()

	opts := &dummyGadgetOpts{}
	for _, opt := range optsF {
		opt(opts)
	}

	InitUnitTest(t)

	runnerOpts := gadgetrunner.GadgetRunnerOpts[any]{
		Image:       gadgetName,
		Timeout:     5 * time.Second,
		ParamValues: opts.paramValues,
	}

	gadgetRunner := gadgetrunner.NewGadgetRunner(t, runnerOpts)
	gadgetRunner.RunGadget()
}
