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
	"bufio"
	"bytes"
	"encoding/json"
	"os/exec"
	"reflect"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/stretchr/testify/require"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var cmpIgnoreUnexported = cmpopts.IgnoreUnexported(
	containercollection.Container{},
	containercollection.K8sMetadata{},
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

func parseJSONArrayOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	entries := []*T{}

	err := json.Unmarshal([]byte(output), &entries)
	require.NoError(t, err, "unmarshaling output array")

	for _, entry := range entries {
		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(entry)
		}
	}

	return entries
}

func parseMultipleJSONArrayOutput[T any](t *testing.T, output string, normalize func(*T)) []*T {
	allEntries := make([]*T, 0)

	sc := bufio.NewScanner(strings.NewReader(output))
	// On ARO we saw arrays with charcounts of > 100,000. Lets just set 1 MB as the limit
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		entries := parseJSONArrayOutput(t, sc.Text(), normalize)
		allEntries = append(allEntries, entries...)
	}
	require.NoError(t, sc.Err(), "parsing multiple JSON arrays")

	return allEntries
}

func expectAllToMatch[T any](t *testing.T, entries []*T, expectedEntry *T) {
	require.NotEmpty(t, entries, "no output entries to match")

	for _, entry := range entries {
		require.Equal(t, expectedEntry, entry, "unexpected output entry")
	}
}

// ExpectAllToMatch verifies that the expectedEntry is matched by all the
// entries in the output (Lines of independent JSON objects).
func ExpectAllToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseMultiJSONOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

// ExpectAllInArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (JSON array of JSON objects).
func ExpectAllInArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseJSONArrayOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

// ExpectAllInMultipleArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectAllInMultipleArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntry *T) {
	entries := parseMultipleJSONArrayOutput(t, output, normalize)
	expectAllToMatch(t, entries, expectedEntry)
}

func expectEntriesToMatch[T any](t *testing.T, entries []*T, expectedEntries ...*T) {
out:
	for _, expectedEntry := range expectedEntries {
		for _, entry := range entries {
			if reflect.DeepEqual(expectedEntry, entry) {
				continue out
			}
		}
		t.Fatalf("output doesn't contain the expected entry: %+v", expectedEntry)
	}
}

// ExpectEntriesToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (Lines of independent JSON objects).
func ExpectEntriesToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseMultiJSONOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

// ExpectEntriesInArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (JSON array of JSON objects).
func ExpectEntriesInArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseJSONArrayOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

// ExpectEntriesInMultipleArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectEntriesInMultipleArrayToMatch[T any](t *testing.T, output string, normalize func(*T), expectedEntries ...*T) {
	entries := parseMultipleJSONArrayOutput(t, output, normalize)
	expectEntriesToMatch(t, entries, expectedEntries...)
}

type CommonDataOption func(commonData *eventtypes.CommonData)

// WithRuntimeMetadata sets the runtime and container name in the common data.
// Notice the container name is taken from the Kubernetes metadata.
func WithRuntimeMetadata(runtime string) CommonDataOption {
	return func(commonData *eventtypes.CommonData) {
		commonData.Runtime.RuntimeName = eventtypes.String2RuntimeName(runtime)
		commonData.Runtime.ContainerName = commonData.K8s.ContainerName
	}
}

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

func BuildBaseEvent(namespace string, options ...CommonDataOption) eventtypes.Event {
	e := eventtypes.Event{
		Type:       eventtypes.NORMAL,
		CommonData: BuildCommonData(namespace),
	}
	for _, option := range options {
		option(&e.CommonData)
	}
	return e
}

func GetTestPodIP(t *testing.T, ns string, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pod ip: %s", stderr.String())
	return string(r)
}

func GetPodIPsFromLabel(t *testing.T, ns string, label string) []string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", "-l", label, "-o", "jsonpath={.items[*].status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pods ips from label: %s", stderr.String())
	return strings.Split(string(r), " ")
}

func GetPodNode(t *testing.T, ns string, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.spec.nodeName}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting pod node: %s", stderr.String())
	return string(r)
}

func GetPodUID(t *testing.T, ns, podname string) string {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.metadata.uid}")
	r, err := cmd.Output()
	require.NoError(t, err, "getting UID of %s/%s: %s", ns, podname, r)
	return string(r)
}

func CheckNamespace(ns string) bool {
	cmd := exec.Command("kubectl", "get", "ns", ns)
	return cmd.Run() == nil
}

// IsDockerRuntime checks whether the container runtime of the first node in the Kubernetes cluster is Docker or not.
func IsDockerRuntime(t *testing.T) bool {
	cmd := exec.Command("kubectl", "get", "node", "-o", "jsonpath={.items[0].status.nodeInfo.containerRuntimeVersion}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	require.NoError(t, err, "getting container runtime: %s", stderr.String())
	ret := string(r)

	return strings.Contains(ret, "docker")
}

// GetIPVersion returns the version of the IP, 4 or 6. It makes the test fail in case of error.
// Based on https://stackoverflow.com/a/48519490
func GetIPVersion(t *testing.T, address string) uint8 {
	if strings.Count(address, ":") < 2 {
		return 4
	} else if strings.Count(address, ":") >= 2 {
		return 6
	}
	t.Fatalf("Failed to determine IP version for address %s", address)
	return 0
}
