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
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/google/go-cmp/cmp"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

func parseOutput[T any](output string, normalize func(*T)) ([]*T, error) {
	ret := []*T{}

	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		var entry T

		line := scanner.Text()
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("unmarshaling line %q: %w", line, err)
		}

		// To be able to use reflect.DeepEqual and cmp.Diff, we need to
		// "normalize" the output so that it only includes non-default values
		// for the fields we are able to verify.
		if normalize != nil {
			normalize(&entry)
		}

		ret = append(ret, &entry)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("parsing output: %w", err)
	}

	return ret, nil
}

// ExpectAllToMatch verifies that the expectedEntry is matched by all the
// entries in the output.
func ExpectAllToMatch[T any](output string, normalize func(*T), expectedEntry *T) error {
	entries, err := parseOutput(output, normalize)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if !reflect.DeepEqual(expectedEntry, entry) {
			return fmt.Errorf("unexpected output entry:\n%s",
				cmp.Diff(expectedEntry, entry))
		}
	}

	return nil
}

// ExpectEntriesToMatch verifies that all the entries in expectedEntries are
// matched by at least one entry in the output.
func ExpectEntriesToMatch[T any](output string, normalize func(*T), expectedEntries ...*T) error {
	entries, err := parseOutput(output, normalize)
	if err != nil {
		return err
	}

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

func BuildBaseEvent(namespace string) eventtypes.Event {
	return eventtypes.Event{
		Type: eventtypes.NORMAL,
		CommonData: eventtypes.CommonData{
			KubernetesNamespace: namespace,
			// Pod and Container name are defined by BusyboxPodCommand.
			KubernetesPodName:       "test-pod",
			KubernetesContainerName: "test-pod",
			// TODO: Include the Node
		},
	}
}
