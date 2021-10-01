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
	"testing"
)

func TestTableFormaterConstructor(t *testing.T) {
	colList := []string{}
	colLens := map[string]int{}

	var table *TableFormater

	table = NewTableFormater(colList, colLens)
	if table == nil {
		t.Fatalf("NewTableFormater() returned nil")
	}

	table = NewTableFormater(nil, nil)
	if table != nil {
		t.Fatalf("NewTableFormater() returned non nil")
	}

	table = NewTableFormater(colList, nil)
	if table != nil {
		t.Fatalf("NewTableFormater() returned non nil")
	}

	table = NewTableFormater(nil, colLens)
	if table != nil {
		t.Fatalf("NewTableFormater() returned non nil")
	}
}

func TestTableFormaterGetHeaderNotWellKnown(t *testing.T) {
	colList := []string{"foo", "bar", "zas"}
	colLens := map[string]int{"foo": 15, "zas": 20}

	table := NewTableFormater(colList, colLens)
	if table == nil {
		t.Fatalf("NewTableFormater() returned nil")
	}

	header := table.GetHeader()

	expected := fmt.Sprintf("%-15s%s %-20s", "FOO", "BAR", "ZAS")

	if header != expected {
		t.Fatalf("%v != %v", header, expected)
	}
}

func TestTableFormaterGetHeaderWellKnown(t *testing.T) {
	colList := []string{"foo", "node", "bar", "pod"}
	colLens := map[string]int{"foo": 15, "zas": 20, "node": 10}

	table := NewTableFormater(colList, colLens)
	if table == nil {
		t.Fatalf("NewTableFormater() returned nil")
	}

	header := table.GetHeader()

	expected := fmt.Sprintf("%-15s%-10s%s %-16s", "FOO", "NODE", "BAR", "POD")

	if header != expected {
		t.Fatalf("%v != %v", header, expected)
	}
}

func TestTableFormaterTransformNotWellKnown(t *testing.T) {
	colList := []string{"foo", "bar", "zas"}
	colLens := map[string]int{"foo": 15, "zas": 20}

	table := NewTableFormater(colList, colLens)
	if table == nil {
		t.Fatalf("NewTableFormater() returned nil")
	}

	transform := table.GetTransformFunc()

	input := `{"bar": 42, "foo": "yes"}`
	output := transform(input)

	// %-4s% because len("bar") + 1 = 4
	expected := fmt.Sprintf("%-15s%-4s%-20s", "yes", "42", "<>")

	if output != expected {
		t.Fatalf("%v != %v", output, expected)
	}
}

func TestTableFormaterTransformWellKnown(t *testing.T) {
	colList := []string{"foo", "node", "bar", "pod"}
	colLens := map[string]int{"foo": 15, "zas": 20, "node": 10}

	table := NewTableFormater(colList, colLens)
	if table == nil {
		t.Fatalf("NewTableFormater() returned nil")
	}

	transform := table.GetTransformFunc()

	input := `{"bar": 42, "node": "ubuntu101", "pod": "mypod"}`
	output := transform(input)

	// %-4s% because len("bar") + 1 = 4
	expected := fmt.Sprintf("%-15s%-10s%-4s%-16s", "<>", "ubuntu101", "42", "mypod")

	if output != expected {
		t.Fatalf("%v != %v", output, expected)
	}
}
