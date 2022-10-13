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

package sort

import (
	"math/rand"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

func TestSorter(t *testing.T) {
	type testEmbedded struct {
		EmbeddedInt int `column:"embeddedInt"`
	}
	type testData struct {
		testEmbedded
		Int     int     `column:"int"`
		Uint    uint    `column:"uint"`
		String  string  `column:"string"`
		Float32 float32 `column:"float32"`
		Float64 float64 `column:"float64"`
		Bool    bool    `column:"bool"`
		Group   string  `column:"group"`
	}
	testEntries := []*testData{
		nil,
		{Int: 1, Uint: 2, String: "c", Float32: 3, Float64: 4, Group: "b", testEmbedded: testEmbedded{EmbeddedInt: 7}},
		nil,
		{Int: 2, Uint: 3, String: "d", Float32: 4, Float64: 5, Group: "b", testEmbedded: testEmbedded{EmbeddedInt: 6}},
		nil,
		{Int: 3, Uint: 4, String: "e", Float32: 5, Float64: 1, Group: "a", testEmbedded: testEmbedded{EmbeddedInt: 5}},
		nil,
		{Int: 4, Uint: 5, String: "a", Float32: 1, Float64: 2, Group: "a", testEmbedded: testEmbedded{EmbeddedInt: 4}},
		nil,
		{Int: 5, Uint: 1, String: "b", Float32: 2, Float64: 3, Group: "c", testEmbedded: testEmbedded{EmbeddedInt: 3}},
		nil,
	}

	// Using shuffle should cover all sorting paths
	rand.Seed(0)

	cols, err := columns.NewColumns[testData]()
	if err != nil {
		t.Errorf("failed to initialize: %v", err)
	}

	cmap := cols.GetColumnMap()

	shuffle := func() {
		rand.Shuffle(len(testEntries), func(i, j int) { testEntries[i], testEntries[j] = testEntries[j], testEntries[i] })
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"uint"})
	if testEntries[0].Uint != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-uint"})
	if testEntries[0].Uint != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"int"})
	if testEntries[0].Int != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-int"})
	if testEntries[0].Int != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"float32"})
	if testEntries[0].Float32 != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float32"})
	if testEntries[0].Float32 != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"float64"})
	if testEntries[0].Float64 != 1 {
		t.Errorf("expected value to be 1")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"-float64"})
	if testEntries[0].Float64 != 5 {
		t.Errorf("expected value to be 5")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"group", "string"})
	if testEntries[0].Group != "a" || testEntries[0].String != "a" {
		t.Errorf("expected value to be a (group) and a (string)")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"embeddedInt"})
	if testEntries[0].EmbeddedInt != 3 {
		t.Errorf("expected embedded value to be a 3")
	}

	shuffle()
	SortEntries(cmap, testEntries, []string{"string"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by unsupported column - should result in noop
	SortEntries(cmap, testEntries, []string{"bool"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by invalid column - should result in noop
	SortEntries(cmap, testEntries, []string{"invalid"})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort by empty column - should result in noop
	SortEntries(cmap, testEntries, []string{""})
	if testEntries[0].String != "a" {
		t.Errorf("expected value to be a")
	}

	// Sort nil array - should result in noop
	SortEntries(cmap, nil, []string{""})
}
