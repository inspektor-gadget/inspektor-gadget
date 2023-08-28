// Copyright 2019-2021 The Inspektor Gadget authors
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

package containerutils

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newRuntimeClient(t *testing.T, runtime types.RuntimeName, sPath string) (runtimeclient.ContainerRuntimeClient, error) {
	config := &containerutilsTypes.RuntimeConfig{
		Name:       runtime,
		SocketPath: sPath,
	}
	rc, err := NewContainerRuntimeClient(config)
	t.Cleanup(func() {
		if rc != nil {
			rc.Close()
		}
	})
	return rc, err
}

func TestNewContainerRuntimeClient(t *testing.T) {
	t.Parallel()

	nonExistingSocketPath := filepath.Join(t.TempDir(), "non-existing-socket")
	for _, runtime := range AvailableRuntimes {
		t.Run(runtime, func(t *testing.T) {
			runtime := types.String2RuntimeName(runtime)
			t.Parallel()

			t.Run("WithNonExistingSocketPath", func(t *testing.T) {
				t.Parallel()

				rc, err := newRuntimeClient(t, runtime, nonExistingSocketPath)
				require.Nil(t, err)
				require.NotNil(t, rc)
			})

			t.Run("WithDefaultSocketPath", func(t *testing.T) {
				t.Parallel()

				rc, err := newRuntimeClient(t, runtime, "")
				require.Nil(t, err)
				require.NotNil(t, rc)
			})
		})
	}
}

func TestParseOCIState(t *testing.T) {
	t.Parallel()

	match, err := filepath.Glob("testdata/*.input")
	if err != nil {
		t.Fatal(err)
	}

	for _, inputFile := range match {
		t.Logf("Parsing OCI state from file %s", inputFile)
		stateBuf, err := os.ReadFile(inputFile)
		if err != nil {
			t.Fatal(err)
		}
		ID, PID, err := ParseOCIState(stateBuf)
		if err != nil {
			t.Errorf("Cannot parse file %s: %s", inputFile, err)
		}
		if ID != "92646e8e819a27d43a9435cd195dc1f38a0c5ff897b4ca660fcbfbfe7502b47a" {
			t.Errorf("Cannot get ID in %s", inputFile)
		}
		if PID != 210223 {
			t.Errorf("Cannot get PID in %s", inputFile)
		}
	}
}
