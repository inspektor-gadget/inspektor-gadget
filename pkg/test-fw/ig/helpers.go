// Copyright 2022 The Inspektor Gadget authors
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

package ig

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func parseMultiJSONOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	ret := []*T{}

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var entry T
		if err := decoder.Decode(&entry); err != nil {
			require.NoError(t, err, "decoding json")
		}
		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(&entry)
		}

		ret = append(ret, &entry)
	}

	return ret
}

func expectEntriesToMatch[T any](t *testing.T, entries []*T, expectedEntries ...*T) {
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

// ExpectEntriesToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (Lines of independent JSON objects).
func ExpectEntriesToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseMultiJSONOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}
