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
	"fmt"
	"os/exec"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

var cmpIgnoreUnexported = cmpopts.IgnoreUnexported(containercollection.Container{})

func parseMultiJSONOutput[T any](output string, normalize func(*T)) ([]*T, error) {
	ret := []*T{}

	decoder := json.NewDecoder(strings.NewReader(output))
	for decoder.More() {
		var entry T
		if err := decoder.Decode(&entry); err != nil {
			return nil, fmt.Errorf("decoding json: %w", err)
		}
		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(&entry)
		}

		ret = append(ret, &entry)
	}

	return ret, nil
}

func parseJSONArrayOutput[T any](output string, normalize func(*T)) ([]*T, error) {
	entries := []*T{}

	if err := json.Unmarshal([]byte(output), &entries); err != nil {
		return nil, fmt.Errorf("unmarshaling output array: %w", err)
	}

	for _, entry := range entries {
		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(entry)
		}
	}

	return entries, nil
}

func parseMultipleJSONArrayOutput[T any](output string, normalize func(*T)) ([]*T, error) {
	allEntries := make([]*T, 0)

	sc := bufio.NewScanner(strings.NewReader(output))
	// On ARO we saw arrays with charcounts of > 100,000. Lets just set 1 MB as the limit
	sc.Buffer(make([]byte, 1024), 1024*1024)
	for sc.Scan() {
		entries, err := parseJSONArrayOutput(sc.Text(), normalize)
		if err != nil {
			return nil, err
		}
		allEntries = append(allEntries, entries...)
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parsing multiple JSON arrays: %w", err)
	}

	return allEntries, nil
}

func expectAllToMatch[T any](entries []*T, expectedEntry *T) error {
	if len(entries) == 0 {
		return fmt.Errorf("no output entries to match")
	}
	for _, entry := range entries {
		if !reflect.DeepEqual(expectedEntry, entry) {
			return fmt.Errorf("unexpected output entry:\n%s",
				cmp.Diff(expectedEntry, entry, cmpIgnoreUnexported))
		}
	}
	return nil
}

// ExpectAllToMatch verifies that the expectedEntry is matched by all the
// entries in the output (Lines of independent JSON objects).
func ExpectAllToMatch[T any](output string, normalize func(*T), expectedEntry *T) error {
	entries, err := parseMultiJSONOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectAllToMatch(entries, expectedEntry)
}

// ExpectAllInArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (JSON array of JSON objects).
func ExpectAllInArrayToMatch[T any](output string, normalize func(*T), expectedEntry *T) error {
	entries, err := parseJSONArrayOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectAllToMatch(entries, expectedEntry)
}

// ExpectAllInMultipleArrayToMatch verifies that the expectedEntry is matched by all the
// entries in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectAllInMultipleArrayToMatch[T any](output string, normalize func(*T), expectedEntry *T) error {
	entries, err := parseMultipleJSONArrayOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectAllToMatch(entries, expectedEntry)
}

func expectEntriesToMatch[T any](entries []*T, expectedEntries ...*T) error {
out:
	for _, expectedEntry := range expectedEntries {
		for _, entry := range entries {
			if reflect.DeepEqual(expectedEntry, entry) {
				continue out
			}
		}
		return fmt.Errorf("output doesn't contain the expected entry: %+v", expectedEntry)
	}
	return nil
}

// ExpectEntriesToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (Lines of independent JSON objects).
func ExpectEntriesToMatch[T any](output string, normalize func(*T), expectedEntries ...*T) error {
	entries, err := parseMultiJSONOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectEntriesToMatch(entries, expectedEntries...)
}

// ExpectEntriesInArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (JSON array of JSON objects).
func ExpectEntriesInArrayToMatch[T any](output string, normalize func(*T), expectedEntries ...*T) error {
	entries, err := parseJSONArrayOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectEntriesToMatch(entries, expectedEntries...)
}

// ExpectEntriesInMultipleArrayToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output (multiple JSON array of JSON objects separated by newlines).
func ExpectEntriesInMultipleArrayToMatch[T any](output string, normalize func(*T), expectedEntries ...*T) error {
	entries, err := parseMultipleJSONArrayOutput(output, normalize)
	if err != nil {
		return err
	}
	return expectEntriesToMatch(entries, expectedEntries...)
}

func BuildCommonData(namespace string) eventtypes.CommonData {
	return eventtypes.CommonData{
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
}

func BuildBaseEvent(namespace string) eventtypes.Event {
	return eventtypes.Event{
		Type:       eventtypes.NORMAL,
		CommonData: BuildCommonData(namespace),
	}
}

func GetTestPodIP(ns string, podname string) (string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(r), nil
}

func GetPodIPsFromLabel(ns string, label string) ([]string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", "-l", label, "-o", "jsonpath={.items[*].status.podIP}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%w: %s", err, stderr.String())
	}
	return strings.Split(string(r), " "), nil
}

func GetPodNode(ns string, podname string) (string, error) {
	cmd := exec.Command("kubectl", "-n", ns, "get", "pod", podname, "-o", "jsonpath={.spec.nodeName}")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	r, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("%w: %s", err, stderr.String())
	}
	return string(r), nil
}

func CheckNamespace(ns string) bool {
	cmd := exec.Command("kubectl", "get", "ns", ns)
	return cmd.Run() == nil
}
