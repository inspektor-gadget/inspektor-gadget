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
	mock := &mockWriter{}

	// Test one single element in the array.
	mock.output = []byte{}
	m := map[string]string{
		"node": "Err/Warn Message",
	}
	printTraceFeedback(mock.Printf, m)
	expected := "Failed to run the gadget on node \"node\": Err/Warn Message"
	if expected != string(mock.output) {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}

	// It should print all the messages because they are not all the same.
	mock.output = []byte{}
	m = map[string]string{
		"node1": "Err/Warn Message 1",
		"node2": "Err/Warn Message 2",
		"node3": "Err/Warn Message 2",
	}
	printTraceFeedback(mock.Printf, m)
	for node, msg := range m {
		expected = fmt.Sprintf("Failed to run the gadget on node \"%s\": %s", node, msg)
		if !strings.Contains(string(mock.output), expected) {
			t.Fatalf("Output %v does not contain %v", string(mock.output), expected)
		}
	}

	// It should print one single message because they are the same.
	mock.output = []byte{}
	m = map[string]string{
		"node1": "Err/Warn Message",
		"node2": "Err/Warn Message",
		"node3": "Err/Warn Message",
	}
	printTraceFeedback(mock.Printf, m)
	expected = "Failed to run the gadget on all nodes: Err/Warn Message"
	if expected != string(mock.output) {
		t.Fatalf("%v != %v", string(mock.output), expected)
	}
}
