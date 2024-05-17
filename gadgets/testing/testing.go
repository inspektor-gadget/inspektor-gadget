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
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func RequireEnvironmentVariables(t testing.TB) {
	if os.Getenv("IG_PATH") == "" {
		t.Skip("environment variable IG_PATH undefined")
	}

	if os.Getenv("IG_RUNTIME") == "" {
		t.Skip("environment variable IG_RUNTIME undefined")
	}

	// TODO: some sanity checks:
	// - if IG_PATH contains kubectl-gadget, then IG_RUNTIME must be kubernetes.
}

// TODO: move to another place?

// GetContainerRuntime returns the container runtime the cluster is using.
func GetContainerRuntime(t *testing.T) string {
	cmd := exec.Command("kubectl", "get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err)

	ret := string(r)
	parts := strings.Split(ret, ":")
	require.GreaterOrEqual(t, len(parts), 1, "unexpected container runtime version")
	return parts[0]
}
