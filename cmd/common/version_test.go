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

package common

import (
	"bytes"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/internal/version"
)

func runVersionCmd(t *testing.T, args ...string) (string, error) {
	t.Helper()

	cmd := NewVersionCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs(args)

	err := cmd.Execute()
	return out.String(), err
}

func TestVersionDefaultOutput(t *testing.T) {
	out, err := runVersionCmd(t)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("v%s\n", version.Version().String()), out)
}

func TestVersionJSONOutput(t *testing.T) {
	out, err := runVersionCmd(t, "-o", "json")
	require.NoError(t, err)

	var versionInfo VersionInfo
	require.NoError(t, json.Unmarshal([]byte(out), &versionInfo))
	require.NotNil(t, versionInfo.ClientVersion)
	assert.Equal(t, version.Version().String(), versionInfo.ClientVersion.Version)
}

func TestVersionInvalidOutputFormat(t *testing.T) {
	_, err := runVersionCmd(t, "-o", "yaml")
	require.Error(t, err)
	assert.ErrorContains(t, err, "invalid output format")
}
