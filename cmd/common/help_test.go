// Copyright 2025 The Inspektor Gadget authors
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

package common

import (
	"os"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
)

// TestRunCommandHelpDoesNotRequireRoot verifies that `ig run -h` and `ig run --help`
// work without root permissions.
func TestRunCommandHelpDoesNotRequireRoot(t *testing.T) {
	// Skip if running as root, since we want to test the non-root behavior
	if os.Geteuid() == 0 {
		t.Skip("Test requires running as non-root user")
	}

	rootCmd := &cobra.Command{
		Use:   "ig",
		Short: "Test command",
	}

	runtime := local.New()
	hiddenColumnTags := []string{"kubernetes"}

	runCmd := NewRunCommand(rootCmd, runtime, hiddenColumnTags, CommandModeRun)
	require.NotNil(t, runCmd)

	// Test -h flag
	runCmd.SetArgs([]string{"-h"})
	err := runCmd.Execute()
	require.NoError(t, err, "Help with -h flag should work without root permissions")

	// Test --help flag
	runCmd.SetArgs([]string{"--help"})
	err = runCmd.Execute()
	require.NoError(t, err, "Help with --help flag should work without root permissions")
}
