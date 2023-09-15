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

package integration

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	columns_json "github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/json"
	runtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func SetEventTimestamp(jsonObj map[string]interface{}, timestamp eventtypes.Time) {
	jsonObj["timestamp"] = timestamp.String()
}

func SetEventMountNsID(jsonObj map[string]interface{}, mountNsID uint64) {
	jsonObj["mntns"] = mountNsID
}

func SetEventRuntimeName(jsonObj map[string]interface{}, runtimeName eventtypes.RuntimeName) {
	runtimeMetadata := jsonObj["runtime"].(map[string]interface{})
	if runtimeMetadata != nil {
		runtimeMetadata["runtimeName"] = runtimeName
	}
}

func SetEventRuntimeContainerID(jsonObj map[string]interface{}, s string) {
	runtimeMetadata := jsonObj["runtime"].(map[string]interface{})
	if runtimeMetadata != nil {
		runtimeMetadata["containerId"] = s
	}
}

func SetEventRuntimeContainerName(jsonObj map[string]interface{}, s string) {
	runtimeMetadata := jsonObj["runtime"].(map[string]interface{})
	if runtimeMetadata != nil {
		runtimeMetadata["containerName"] = s
	}
}

func SetEventK8sNode(jsonObj map[string]interface{}, s string) {
	k8sMetadata := jsonObj["k8s"].(map[string]interface{})
	if k8sMetadata != nil {
		k8sMetadata["node"] = s
	}
}

func SetEventK8sNamespace(jsonObj map[string]interface{}, s string) {
	k8sMetadata := jsonObj["k8s"].(map[string]interface{})
	if k8sMetadata != nil {
		k8sMetadata["namespace"] = s
	}
}

func SetEventK8sPod(jsonObj map[string]interface{}, s string) {
	k8sMetadata := jsonObj["k8s"].(map[string]interface{})
	if k8sMetadata != nil {
		k8sMetadata["pod"] = s
	}
}

func SetEventK8sContainer(jsonObj map[string]interface{}, s string) {
	k8sMetadata := jsonObj["k8s"].(map[string]interface{})
	if k8sMetadata != nil {
		k8sMetadata["container"] = s
	}
}

func SetEventK8sHostNetwork(jsonObj map[string]interface{}, b bool) {
	k8sMetadata := jsonObj["k8s"].(map[string]interface{})
	if k8sMetadata != nil {
		k8sMetadata["hostNetwork"] = b
	}
}

func RunEventToObj(t *testing.T, ev *runtypes.Event) map[string]interface{} {
	cols := columns.MustCreateColumns[runtypes.Event]()
	jsonFormatter := columns_json.NewFormatter[runtypes.Event](cols.GetColumnMap())

	jsonStr := jsonFormatter.FormatEntry(ev)

	var jsonObj map[string]interface{}
	err := json.Unmarshal([]byte(jsonStr), &jsonObj)
	require.NoError(t, err, "unmarshalling event json")

	delete(jsonObj, "raw_data")
	delete(jsonObj, "data")

	return jsonObj
}

// MergeJsonObjs merges two JSON objects (map[string]interface{}) and returns a copy.
// The original objects are not modified in order to use the base for multiple merges.
// If a key exists in both objects, the function fails.
func MergeJsonObjs(t *testing.T, base map[string]interface{}, additionalFields map[string]interface{}) map[string]interface{} {
	// First copy the base map
	target := map[string]interface{}{}
	for k, v := range base {
		target[k] = v
	}
	// Then merge the additional fields and fail if a field already exists
	for k, v := range additionalFields {
		_, ok := target[k]
		require.False(t, ok, fmt.Sprintf("key %s already exists in target map", k))
		target[k] = v
	}
	return target
}

// parseMultiJSONOutputToObj parses a string containing multiple JSON objects
// (one per line) into a slice of maps.
func parseMultiJSONOutputToObj(t *testing.T, output string, normalize func(map[string]interface{})) []map[string]interface{} {
	ret := []map[string]interface{}{}

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var entry map[string]interface{}
		err := decoder.Decode(&entry)
		require.NoError(t, err, "decoding json")

		if normalize != nil {
			normalize(entry)
		}

		// Marshal & Unmarshal to have the right types in the map
		bytes, err := json.Marshal(entry)
		require.NoError(t, err, "marshalling json")

		err = json.Unmarshal(bytes, &entry)
		require.NoError(t, err, "unmarshalling json")
		ret = append(ret, entry)
	}
	return ret
}

// expectEntriesToMatchObj verifies that all the entries in expectedEntries are
// matched by at least one entry in the output
func expectEntriesToMatchObj(t *testing.T, entries []map[string]interface{}, expectedEntries ...map[string]interface{}) {
out:
	for _, expectedEntry := range expectedEntries { // Marshal & Unmarshal to have the right types in the map
		bytes, err := json.Marshal(expectedEntry)
		require.NoError(t, err, "marshalling expectedEntry")
		err = json.Unmarshal(bytes, &expectedEntry)
		require.NoError(t, err, "unmarshalling expectedEntry")

		for _, entry := range entries {
			if reflect.DeepEqual(expectedEntry, entry) {
				continue out
			}
		}
		expectedJsonEntry, _ := json.Marshal(expectedEntry)
		t.Fatalf("output doesn't contain the expected entry: %+v", string(expectedJsonEntry))
	}
}

// ExpectEntriesToMatchObj verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (Lines of independent JSON objects).
func ExpectEntriesToMatchObj(t *testing.T, output string, normalize func(map[string]interface{}), expectedEntries ...map[string]interface{}) {
	entries := parseMultiJSONOutputToObj(t, output, normalize)
	expectEntriesToMatchObj(t, entries, expectedEntries...)
}
