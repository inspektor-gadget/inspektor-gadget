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
	"testing"

	"github.com/cilium/ebpf/rlimit"
	"github.com/moby/moby/pkg/parsers/kernel"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
)

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

func MinimumKernelVersion(t testing.TB, minKernelVersion string) {
	t.Helper()
	currVersion, err := kernel.GetKernelVersion()
	require.NoError(t, err, "Failed to get kernel version: %s", err)

	minVersion, err := kernel.ParseRelease(minKernelVersion)
	require.NoError(t, err, "Failed to parse minKernelVersion: %s", err)

	if kernel.CompareKernelVersion(*currVersion, *minVersion) < 0 {
		t.Skipf("Skipping test because kernel version %s is less than %s", currVersion, minKernelVersion)
	}
}

func InitUnitTest(t testing.TB) {
	utilstest.RequireRoot(t)
	RemoveMemlock(t)
}
