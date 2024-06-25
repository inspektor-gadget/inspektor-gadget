// Copyright 2024 The Inspektor Gadget authors
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

// Package match provides various helper functions for matching actual output to
// expected output.
package match

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type testEvent struct {
	Foo int    `json:"foo"`
	Bar string `json:"bar"`
}

func TestSingleObject(t *testing.T) {
	input := `{"foo": 1, "bar": "baz"}`
	expected := &testEvent{Foo: 1, Bar: "baz"}
	actualArr := decodeJSONOutput(t, JSONSingleObjectMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 1)
	assert.Equal(t, expected, actualArr[0])
}

func TestMultiObject(t *testing.T) {
	input := `{"foo": 1, "bar": "baz"}
	{"foo": 2, "bar": "baz2"}`
	expected := []*testEvent{
		{Foo: 1, Bar: "baz"},
		{Foo: 2, Bar: "baz2"},
	}
	actualArr := decodeJSONOutput(t, JSONMultiObjectMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 2)
	assert.Equal(t, expected, actualArr)
}

func TestMultiObjectSameLine(t *testing.T) {
	input := `{"foo": 1, "bar": "baz"}{"foo": 2, "bar": "baz2"}`
	expected := []*testEvent{
		{Foo: 1, Bar: "baz"},
		{Foo: 2, Bar: "baz2"},
	}
	actualArr := decodeJSONOutput(t, JSONMultiObjectMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 2)
	assert.Equal(t, expected, actualArr)
}

func TestSingleArray(t *testing.T) {
	input := `[{"foo": 1, "bar": "baz"}]`
	expected := []*testEvent{
		{Foo: 1, Bar: "baz"},
	}
	actualArr := decodeJSONOutput(t, JSONSingleArrayMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 1)
	assert.Equal(t, expected, actualArr)
}

func TestMultiArray(t *testing.T) {
	input := `[{"foo": 1, "bar": "baz"}]
	[{"foo": 2, "bar": "baz2"}]`
	expected := []*testEvent{
		{Foo: 1, Bar: "baz"},
		{Foo: 2, Bar: "baz2"},
	}
	actualArr := decodeJSONOutput(t, JSONMultiArrayMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 2)
	assert.Equal(t, expected, actualArr)
}

func TestMultiArraySameLine(t *testing.T) {
	input := `[{"foo": 1, "bar": "baz"}][{"foo": 2, "bar": "baz2"}]`
	expected := []*testEvent{
		{Foo: 1, Bar: "baz"},
		{Foo: 2, Bar: "baz2"},
	}
	actualArr := decodeJSONOutput(t, JSONMultiArrayMode, input, func(*testEvent) {})

	require.Len(t, actualArr, 2)
	assert.Equal(t, expected, actualArr)
}
