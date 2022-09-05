// Copyright 2019-2021 The Inspektor Gadget authors
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

package utils

import (
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

func TestGetIdenticalValue(t *testing.T) {
	if v := getIdenticalValue(nil); v != "" {
		t.Fatalf("Invalid identical value '%s' from nil map", v)
	}

	m := make(map[string]string)
	if v := getIdenticalValue(m); v != "" {
		t.Fatalf("Invalid identical value '%s' from %+v", v, m)
	}

	m = map[string]string{
		"key1": "value1",
		"key2": "value2",
	}
	if v := getIdenticalValue(m); v != "" {
		t.Fatalf("Invalid identical value '%s' from %+v", v, m)
	}

	m = map[string]string{
		"key1": "value1",
		"key2": "value1",
		"key3": "value2",
		"key4": "value2",
	}
	if v := getIdenticalValue(m); v != "" {
		t.Fatalf("Invalid identical value '%s' from %+v", v, m)
	}

	m = map[string]string{
		"key": "value",
	}
	if v := getIdenticalValue(m); v != "value" {
		t.Fatalf("Invalid identical value '%s' from %+v", v, m)
	}

	m = map[string]string{
		"key1": "value",
		"key2": "value",
	}
	if v := getIdenticalValue(m); v != "value" {
		t.Fatalf("Invalid identical value '%s' from %+v", v, m)
	}
}

func (mock *mockWriter) Printf(format string, args ...interface{}) {
	mock.output = append(mock.output, []byte(fmt.Sprintf(format, args...))...)
}

func TestPrintTraceFeedback(t *testing.T) {
	// get reference to original stderr and restore on exit
	originalStderr := os.Stderr
	defer func() { os.Stderr = originalStderr }()

	var out string

	runprintTraceFeedback := func(p string, m map[string]string, n int) string {
		r, w, _ := os.Pipe()
		os.Stderr = w
		printTraceFeedback(p, m, n)
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stderr = originalStderr

		return string(out)
	}

	// Test one single element in the array.
	m := map[string]string{
		"node": "Err/Warn Message",
	}

	out = runprintTraceFeedback("MyPrefix", m, 1)
	expected := "MyPrefix: failed to run gadget on node \"node\": Err/Warn Message\n"
	if expected != out {
		t.Fatalf("'%v' != '%v'", out, expected)
	}

	// It should print all the messages because they are not all the same.
	m = map[string]string{
		"node1": "Err/Warn Message 1",
		"node2": "Err/Warn Message 2",
		"node3": "Err/Warn Message 2",
	}
	out = runprintTraceFeedback("MyPrefix2", m, 3)
	for node, msg := range m {
		expected = fmt.Sprintf("MyPrefix2: failed to run gadget on node \"%s\": %s", node, msg)
		if !strings.Contains(out, expected) {
			t.Fatalf("Output '%v' does not contain '%v'", out, expected)
		}
	}

	// It should print all the messages because even if they are all the same,
	// there was a node that didn't report an error. Therefore, the final error
	// message can say "failed to run gadget on all nodes" but only on the ones
	// that it really failed.
	m = map[string]string{
		"node2": "Err/Warn Message 2",
		"node3": "Err/Warn Message 2",
	}
	out = runprintTraceFeedback("MyPrefix3", m, 3)
	for node, msg := range m {
		expected = fmt.Sprintf("MyPrefix3: failed to run gadget on node \"%s\": %s", node, msg)
		if !strings.Contains(out, expected) {
			t.Fatalf("Output '%v' does not contain '%v'", out, expected)
		}
	}

	// It should print one single message because they are the same.
	m = map[string]string{
		"node1": "Err/Warn Message",
		"node2": "Err/Warn Message",
		"node3": "Err/Warn Message",
	}
	out = runprintTraceFeedback("MyPrefix4", m, 3)
	expected = "MyPrefix4: failed to run gadget on all nodes: Err/Warn Message\n"
	if expected != out {
		t.Fatalf("'%v' != '%v'", out, expected)
	}
}
