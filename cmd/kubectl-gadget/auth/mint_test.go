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

package auth

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseServiceAccount(t *testing.T) {
	for _, test := range []struct {
		value     string
		namespace string
		name      string
		wantErr   bool
	}{
		{value: "team-a/ig-client", namespace: "team-a", name: "ig-client"},
		{value: "ig-client", wantErr: true},
		{value: "/ig-client", wantErr: true},
		{value: "team-a/", wantErr: true},
		{value: "team-a/ig/client", wantErr: true},
	} {
		namespace, name, err := parseServiceAccount(test.value)
		if test.wantErr {
			assert.Error(t, err)
			continue
		}
		require.NoError(t, err)
		assert.Equal(t, test.namespace, namespace)
		assert.Equal(t, test.name, name)
	}
}
