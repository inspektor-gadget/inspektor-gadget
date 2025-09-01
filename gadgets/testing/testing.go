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
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"

	"github.com/cilium/ebpf/rlimit"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/utils"
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
	utilstest.RequireRoot(t)
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
