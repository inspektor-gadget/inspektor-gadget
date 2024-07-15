// Copyright 2024 The Inspektor Gadget authors
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

package datasource

import (
	"maps"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func TestDataSourceFieldConfig(t *testing.T) {
	type testCase struct {
		name                string
		expectedAnnotations map[string]string
		expectedFlags       FieldFlag
		config              string
	}

	testCases := []testCase{
		{
			name:   "no-anotations",
			config: "",
		},
		{
			name: "columns.hidden",
			expectedAnnotations: map[string]string{
				"columns.hidden": "true",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.hidden: true
`,
		},
		{
			name: "many-annotations",
			expectedAnnotations: map[string]string{
				"columns.width":    "40",
				"columns.maxwidth": "80",
				"foo-ann":          "yes",
			},
			expectedFlags: FieldFlagHidden,
			config: `
fields:
  foo:
    annotations:
      columns.width: 40
      columns.maxwidth: 80
      foo-ann: yes
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			err := v.ReadConfig(strings.NewReader(tc.config))
			require.NoError(t, err)

			ds, err := New(TypeArray, "myds", WithConfig(v))
			require.NoError(t, err)

			fooAcc, err := ds.AddField("foo", api.Kind_String)
			require.NoError(t, err)

			expectedAnnotations := maps.Clone(defaultFieldAnnotations)
			maps.Copy(expectedAnnotations, tc.expectedAnnotations)

			assert.Equal(t, fooAcc.Annotations(), expectedAnnotations)
		})
	}
}
