// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package json

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWithFields(t *testing.T) {
	tests := []struct {
		name      string
		fields    []string
		formatter *Formatter
		expected  *Formatter
	}{
		{
			name:   "useDefault is stays true when fields is nil",
			fields: nil,
			formatter: &Formatter{
				useDefault: true,
			},
			expected: &Formatter{
				useDefault: true,
			},
		},
		{
			name:      "useDefault is set to false when fields is and formatter are nil",
			fields:    nil,
			formatter: &Formatter{},
			expected:  &Formatter{},
		},
		{
			name:   "useDefault is set false when fields is nil",
			fields: nil,
			formatter: &Formatter{
				useDefault: false,
			},
			expected: &Formatter{},
		},
		{
			name:   "when fields is not nil",
			fields: []string{"field1", "field2"},
			formatter: &Formatter{
				useDefault: false,
			},
			expected: &Formatter{
				useDefault: false,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actual := WithFields(test.fields)
			actual(test.formatter)
			assert.Equal(t, test.expected.useDefault, test.formatter.useDefault)
		})
	}
}

func TestWithShowAll(t *testing.T) {
	tests := []struct {
		name     string
		val      bool
		expected *Formatter
	}{
		{
			name: "when val is false",
			val:  false,
			expected: &Formatter{
				showAll:    false,
				useDefault: true,
			},
		},
		{
			name: "when val is true",
			val:  true,
			expected: &Formatter{
				showAll:    true,
				useDefault: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			form := &Formatter{}
			actual := WithShowAll(test.val)
			actual(form)
			assert.Equal(t, test.expected.useDefault, form.useDefault)
			assert.Equal(t, test.expected.showAll, form.showAll)
		})
	}
}

func TestWithPretty(t *testing.T) {
	tests := []struct {
		name     string
		val      bool
		indent   string
		expected *Formatter
	}{
		{
			name:   "when val is false",
			val:    false,
			indent: "",
			expected: &Formatter{
				pretty: false,
				indent: "",
			},
		},
		{
			name:   "when val is true",
			val:    true,
			indent: "indent",
			expected: &Formatter{
				pretty: true,
				indent: "indent",
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			form := &Formatter{}
			actual := WithPretty(test.val, test.indent)
			actual(form)
			assert.Equal(t, test.expected.pretty, form.pretty)
			assert.Equal(t, test.expected.indent, form.indent)
		})
	}
}

func TestWithArray(t *testing.T) {
	tests := []struct {
		name     string
		val      bool
		expected *Formatter
	}{
		{
			name: "when val is false",
			val:  false,
			expected: &Formatter{
				array: false,
			},
		},
		{
			name: "when val is true",
			val:  true,
			expected: &Formatter{
				array: true,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			form := &Formatter{}
			actual := WithArray(test.val)
			actual(form)
			assert.Equal(t, test.expected.array, form.array)
		})
	}
}
