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

package clioperator

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCliOperators(t *testing.T) {
	type testCase struct {
		name            string
		inputVals       []string
		expectedDefault string
		expectedYaml    string
		expectedJson    string
	}
	testCases := []testCase{
		{
			name:            "Single field with value",
			inputVals:       []string{"hello"},
			expectedDefault: "hello",
			expectedYaml:    "---\ntest0: hello\n",
			expectedJson:    "{\"test0\":\"hello\"}\n",
		},
		{
			name:            "Multiple fields with values",
			inputVals:       []string{"foo", "bar", "baz"},
			expectedDefault: "foobarbaz",
			expectedYaml:    "---\ntest0: foo\ntest1: bar\ntest2: baz\n",
			expectedJson:    "{\"test0\":\"foo\",\"test1\":\"bar\",\"test2\":\"baz\"}\n",
		},
		{
			name:            "Empty value in field",
			inputVals:       []string{"value1", "", "value2"},
			expectedDefault: "value1value2",
			expectedYaml:    "---\ntest0: value1\ntest1: \"\"\ntest2: value2\n",
			expectedJson:    "{\"test0\":\"value1\",\"test1\":\"\",\"test2\":\"value2\"}\n",
		},
		{
			name:            "All fields empty",
			inputVals:       []string{"", "", ""},
			expectedDefault: "",
			expectedYaml:    "---\ntest0: \"\"\ntest1: \"\"\ntest2: \"\"\n",
			expectedJson:    "{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\"}\n",
		},
		{
			name:            "Numbers as strings",
			inputVals:       []string{"123", "456", "789"},
			expectedDefault: "123456789",
			expectedYaml:    "---\ntest0: \"123\"\ntest1: \"456\"\ntest2: \"789\"\n",
			expectedJson:    "{\"test0\":\"123\",\"test1\":\"456\",\"test2\":\"789\"}\n",
		},
	}

	for _, tc := range testCases {
		for _, mode := range []string{"default", "yaml", "json"} {
			t.Run(tc.name+mode, func(t *testing.T) {
				ds, _ := datasource.New(datasource.TypeSingle, "test")
				var fas []datasource.FieldAccessor
				for i := range tc.inputVals {
					fa, err := ds.AddField(fmt.Sprintf("test%d", i), api.Kind_String)
					require.NoError(t, err)
					require.NotNil(t, fa)
					fas = append(fas, fa)
				}
				data, _ := ds.NewPacketSingle()

				for i, fa := range fas {
					require.Greater(t, len(tc.inputVals), i)
					err := fa.PutString(data, tc.inputVals[i])
					require.NoError(t, err)
				}
				var buf bytes.Buffer
				switch mode {
				case "default":
					defaultDataFn(ds, data, &buf)
					assert.Equal(t, tc.expectedDefault, buf.String())
				case "yaml":
					jsonFormatter, _ := json.New(ds,
						json.WithShowAll(true),
						json.WithPretty(true, "  "),
						json.WithArray(true),
					)
					yamlDataFn(ds, data, jsonFormatter, &buf)
					assert.Equal(t, tc.expectedYaml, buf.String())
				case "json":
					jsonFormatter, _ := json.New(ds,
						json.WithShowAll(true),
					)
					jsonSingleDataFn(ds, data, jsonFormatter, &buf)
					assert.Equal(t, tc.expectedJson, buf.String())

				default:
					t.Errorf("Unknown mode: %s", mode)
				}
			})
		}
	}
}

func TestJsonArray(t *testing.T) {
	type testCase struct {
		name      string
		inputVals []string
		expected  string
	}
	testCases := []testCase{
		{
			name:      "Single field with value",
			inputVals: []string{"hello", "world"},
			expected:  "[{\"test0\":\"hello\",\"test1\":\"\"},{\"test0\":\"\",\"test1\":\"world\"}]\n",
		},
		{
			name:      "Single field with a long string",
			inputVals: []string{"this is a very long string that goes beyond the usual length for testing purposes"},
			expected:  "[{\"test0\":\"this is a very long string that goes beyond the usual length for testing purposes\"}]\n",
		},
		{
			name:      "Empty field",
			inputVals: []string{""},
			expected:  "[{\"test0\":\"\"}]\n",
		},
		{
			name:      "More fields than values",
			inputVals: []string{"one", "two"},
			expected:  "[{\"test0\":\"one\",\"test1\":\"\"},{\"test0\":\"\",\"test1\":\"two\"}]\n",
		},
		{
			name:      "Empty input values",
			inputVals: []string{},
			expected:  "[]\n",
		},
		{
			name:      "Large number of fields",
			inputVals: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j"},
			expected:  "[{\"test0\":\"a\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"b\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"c\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"d\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"e\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"f\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"g\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"h\",\"test8\":\"\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"i\",\"test9\":\"\"},{\"test0\":\"\",\"test1\":\"\",\"test2\":\"\",\"test3\":\"\",\"test4\":\"\",\"test5\":\"\",\"test6\":\"\",\"test7\":\"\",\"test8\":\"\",\"test9\":\"j\"}]\n",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds, _ := datasource.New(datasource.TypeArray, "test")
			var fas []datasource.FieldAccessor
			for i := range tc.inputVals {
				fa, err := ds.AddField(fmt.Sprintf("test%d", i), api.Kind_String)
				require.NoError(t, err)
				require.NotNil(t, fa)
				fas = append(fas, fa)
			}
			data, _ := ds.NewPacketArray()

			for i, fa := range fas {
				data.Append(data.New())
				err := fa.PutString(data.Get(data.Len()-1), tc.inputVals[i])
				require.NoError(t, err)

			}
			var buf bytes.Buffer
			jsonFormatter, _ := json.New(ds,
				json.WithShowAll(true),
				json.WithArray(true),
			)
			jsonArrayDataFn(ds, data, jsonFormatter, &buf)
			assert.Equal(t, tc.expected, buf.String())
		})
	}
}
