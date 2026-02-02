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

package containercollection

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeRuntimeID(t *testing.T) {
	require.Equal(t, "", normalizeRuntimeID(""))
	require.Equal(t, "abc", normalizeRuntimeID("abc"))
	require.Equal(t, "deadbeef", normalizeRuntimeID("docker://deadbeef"))
	require.Equal(t, "deadbeef", normalizeRuntimeID("containerd://deadbeef"))
}

func TestParseServiceNameFromGroup(t *testing.T) {
	require.Equal(t, "myservice", parseServiceNameFromGroup("service:myservice"))
	require.Equal(t, "other", parseServiceNameFromGroup("other"))
	require.Equal(t, "", parseServiceNameFromGroup(""))
}

func TestParseTaskFamilyRevision(t *testing.T) {
	fam, rev := parseTaskFamilyRevision("arn:aws:ecs:us-east-1:123:task-definition/myfamily:42")
	require.Equal(t, "myfamily", fam)
	require.Equal(t, "42", rev)

	fam, rev = parseTaskFamilyRevision("myfamily:7")
	require.Equal(t, "", fam) // no slash => best effort returns empty
	require.Equal(t, "", rev)

	fam, rev = parseTaskFamilyRevision("arn:aws:ecs:us-east-1:123:task-definition/myfamily")
	require.Equal(t, "myfamily", fam)
	require.Equal(t, "", rev)
}
