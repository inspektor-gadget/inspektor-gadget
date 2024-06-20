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

// Package match provides various helper functions for matching actual output to
// expected output.
package match

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// OutputMode represents how the output string should be parsed.
type OutputMode int

const (
	InvalidMode OutputMode = iota

	// JSONSingleObjectMode represents the mode in which the output is single
	// JSON object.
	//
	// Example: One object in one line:
	// {"key": "value1", "key2": "value4"}
	//
	// Example: Object spread across multiple lines:
	//{
	//	"key": "value1",
	//	"key2": "value4"
	//}
	//
	// Currently not known gadget produces this output.
	JSONSingleObjectMode

	// JSONMultiObjectMode represents the mode in which the output is one or multiple
	// JSON objects.
	//
	// Example: One object per line:
	// {"key": "value1", "key2": "value4"}
	// {"key": "value2", "key2": "value5"}
	// {"key": "value3", "key2": "value6"}
	//
	// Example: Object spread across multiple lines:
	//{
	//	"key": "value1",
	//	"key2": "value4"
	//}
	//{
	//	"key": "value2",
	//	"key2": "value5"
	//}
	//{
	//	"key": "value3",
	//	"key2": "value6"
	//}
	//
	// This output is produced by gadgets like trace_open, trace_exec, etc.
	JSONMultiObjectMode

	// JSONSingleArrayMode represents the mode in which the output a single JSON
	// array.
	//
	// Example: Single array in one line:
	// [{"key": "value1"}, {"key": "value2"}, {"key": "value3"}]
	//
	// Example: Single array in multiple lines:
	// [
	// 	{
	// 		"key": "value1"
	// 	},
	// 	{
	// 		"key": "value2"
	// 	},
	// 	{
	// 		"key": "value3"
	// 	}
	// ]
	//
	// This output is produced by gadgets like snapshot_process, snapshot_socket, etc.
	JSONSingleArrayMode

	// JSONMultiArrayMode represents the mode in which the output is one or multiple
	// JSON arrays.
	//
	// Example: Multiple arrays, one per line:
	// [{"key": "value1"}, {"key": "value2"}, {"key": "value3"}]
	// [{"key": "value4"}, {"key": "value5"}, {"key": "value4"}]
	//
	// Example: Multiple arrays, in multiple lines:
	// [
	// 	{
	// 		"key": "value1"
	// 	},
	// 	{
	// 		"key": "value2"
	// 	},
	// 	{
	// 		"key": "value3"
	// 	}
	// ]
	// [
	// 	{
	// 		"key": "value4"
	// 	},
	// 	{
	// 		"key": "value5"
	// 	},
	// 	{
	// 		"key": "value4"
	// 	}
	// ]
	//
	// This output is produced by gadgets like top_file, top_tcp, etc.
	JSONMultiArrayMode
)

// MatchEntries verifies that all the entries in expectedEntries are matched by
// at least one entry in the output. The output is parsed according to outputMode.
func MatchEntries[T any](t *testing.T, outputMode OutputMode, output string, normalize func(*T), expectedEntries ...*T) {
	entries := decodeJSONOutput(t, outputMode, output, normalize)
	MatchUnmarshalledEntries(t, entries, expectedEntries...)
}

// MatchAllEntries verifies that expectedEntry is matched by all entries in the
// output. The output is parsed according to outputMode.
func MatchAllEntries[T any](t *testing.T, outputMode OutputMode, output string, normalize func(*T), expectedEntry *T) {
	entries := decodeJSONOutput(t, outputMode, output, normalize)

	require.NotEmpty(t, entries, "no output entries to match")

	for _, entry := range entries {
		require.Equal(t, expectedEntry, entry, "unexpected output entry")
	}
}

// MatchUnmarshalledEntries verifies that all the entries in expectedEntries are
// matched by at least one entry in entries.
// MatchUnmarshalledEntries([]int{1, 2, 3}, 2, 3) will pass
// MatchUnmarshalledEntries([]int{1, 2, 3}, 2, 4) will fail
func MatchUnmarshalledEntries[T any](t *testing.T, entries []*T, expectedEntries ...*T) {
out:
	for _, expectedEntry := range expectedEntries {
		for _, entry := range entries {
			if reflect.DeepEqual(expectedEntry, entry) {
				continue out
			}
		}

		var str strings.Builder

		str.WriteString("output doesn't contain the expected entry\n")
		str.WriteString("captured:\n")
		for _, entry := range entries {
			entryJson, _ := json.Marshal(entry)
			str.WriteString(string(entryJson))
			str.WriteString("\n")
		}
		expectedEntryJson, _ := json.Marshal(expectedEntry)
		str.WriteString("expected:\n")
		str.WriteString(string(expectedEntryJson))
		t.Fatal(str.String())
	}
}

// EqualString verifies that the output string matches the expectedString.
// This function can be directly used as ValidateOutput function.
func EqualString(t *testing.T, expectedString string) func(t *testing.T, output string) {
	return func(t *testing.T, output string) {
		require.Equal(t, expectedString, output, "output didn't match the expected string")
	}
}

// MatchRegexp verifies that the output string matches the expected regular expression.
// This function can be directly used as ValidateOutput function.
func MatchRegexp(t *testing.T, expectedRegexp string) func(t *testing.T, output string) {
	return func(t *testing.T, output string) {
		require.Regexp(t, expectedRegexp, output, "output didn't match the expected regexp")
	}
}

func decodeJSONOutput[T any](t *testing.T, outputMode OutputMode, output string, normalize func(*T)) []*T {
	var entries []*T

	switch outputMode {
	case JSONSingleObjectMode:
		entries = decodeJSONObjects[T](t, output, true)
	case JSONMultiObjectMode:
		entries = decodeJSONObjects[T](t, output, false)
	case JSONSingleArrayMode:
		entries = decodeJSONArrays[T](t, output, true)
	case JSONMultiArrayMode:
		entries = decodeJSONArrays[T](t, output, false)
	default:
		t.Fatalf("Invalid mode: %d", outputMode)
	}

	// To be able to use reflect.DeepEqual and cmp.Diff, we need to
	// "normalize" the output so that it only includes non-default values
	// for the fields we are able to verify.
	if normalize != nil {
		for _, entry := range entries {
			normalize(entry)
		}
	}

	return entries
}

// decodeJSONObjects decodes the output string that contains one or multiple
// JSON objects.
func decodeJSONObjects[T any](t *testing.T, output string, single bool) []*T {
	ret := []*T{}

	c := 0

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var entry T
		if err := decoder.Decode(&entry); err != nil {
			require.NoError(t, err, "decoding json")
		}

		if single && c > 0 {
			t.Fatalf("expected a single object, but found multiple objects")
		}
		c++
		ret = append(ret, &entry)
	}

	return ret
}

// decodeJSONArrays parses the output string that contains one or multiple JSON
// arrays. It returns a slice of pointers to the decoded objects.
func decodeJSONArrays[T any](t *testing.T, output string, single bool) []*T {
	allEntries := make([]*T, 0)

	c := 0

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		entries := []*T{}
		if err := decoder.Decode(&entries); err != nil {
			require.NoError(t, err, "decoding json")
		}

		if single && c > 0 {
			t.Fatalf("expected a single array, but found multiple arrays")
		}
		c++
		allEntries = append(allEntries, entries...)
	}

	return allEntries
}
