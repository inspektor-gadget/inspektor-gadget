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

// Package match provides various helper functions for matching actual output to expected output.
package match

import (
	"encoding/json"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var DefaultTestComponent string

const (
	IgTestComponent              = "ig"
	InspektorGadgetTestComponent = "kubectl-gadget"
)

func ParseMultiJSONOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
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

func ExpectNormalizedEntriesToMatch[T any](t *testing.T, entries []*T, expectedEntries ...*T) {
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
	entries := ParseMultiJSONOutput(t, output, normalize)
	ExpectNormalizedEntriesToMatch(t, entries, expectedEntries...)
}

// ExpectStringToMatch verifies that the output string matches the expectedString.
// This function can be directly used as ValidateOutput function.
func ExpectStringToMatch(t *testing.T, expectedString string) func(t *testing.T, output string) {
	return func(t *testing.T, output string) {
		require.Equal(t, expectedString, output, "output didn't match the expected string")
	}
}

// ExpectRegexpToMatch verifies that the output string matches the expected regular expression.
// This function can be directly used as ValidateOutput function.
func ExpectRegexpToMatch(t *testing.T, expectedRegexp string) func(t *testing.T, output string) {
	return func(t *testing.T, output string) {
		r := regexp.MustCompile(expectedRegexp)
		if !r.MatchString(output) {
			t.Fatalf("output didn't match the expected regexp: %s", expectedRegexp)
		}
	}
}

type CommonDataOption func(commonData *eventtypes.CommonData)

// WithContainerImageName sets the ContainerImageName to facilitate the tests
func WithContainerImageName(imageName string, isDockerRuntime bool) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		if !isDockerRuntime {
			commonData.Runtime.ContainerImageName = imageName
		}
	}
}

func BuildCommonData(namespace string, options ...CommonDataOption) eventtypes.CommonData {
	e := eventtypes.CommonData{
		K8s: eventtypes.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace: namespace,
				// Pod and Container name are defined by BusyboxPodCommand.
				PodName:       "test-pod",
				ContainerName: "test-pod",
			},
		},
		// TODO: Include the Node
	}
	for _, option := range options {
		option(&e)
	}
	return e
}

func SetDefaultTestComponent() {
	DefaultTestComponent = IgTestComponent
	if strings.Contains(os.Getenv("IG_PATH"), InspektorGadgetTestComponent) {
		DefaultTestComponent = InspektorGadgetTestComponent
	}
}

func NormalizeCommonData(e *eventtypes.CommonData, ns string) {
	switch DefaultTestComponent {
	case InspektorGadgetTestComponent:
		e.Runtime.ContainerID = ""
		e.K8s.Node = ""
		// TODO: Verify container runtime and container name
		e.Runtime.RuntimeName = ""
		e.Runtime.ContainerName = ""
	}
}
