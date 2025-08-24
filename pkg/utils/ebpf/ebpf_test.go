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

package ebpfutils

import (
	"testing"

	"github.com/cilium/ebpf"
	"github.com/stretchr/testify/assert"
)

func TestSpecSetVars(t *testing.T) {
	tests := []struct {
		description   string
		spec          *ebpf.CollectionSpec
		values        map[string]interface{}
		hasError      bool
		expectedError string
	}{
		{
			description: "variables not found",
			spec: &ebpf.CollectionSpec{
				Variables: map[string]*ebpf.VariableSpec{
					"test": {},
					"foo":  {},
					"bar":  {},
					"baz":  {},
				},
			},
			values: map[string]interface{}{
				"bat": "test",
			},
			hasError:      true,
			expectedError: "variable \"bat\" not found on ebpf spec: file does not exist",
		},
		{
			description: "not marshaling value",
			spec: &ebpf.CollectionSpec{
				Variables: map[string]*ebpf.VariableSpec{
					"foo":  {},
					"bar":  {},
					"baz":  {},
					"test": {},
				},
			},
			values: map[string]interface{}{
				"foo": "test",
			},
			hasError:      true,
			expectedError: "setting \"foo\" variable: marshaling value : string doesn't marshal to 0 bytes",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := SpecSetVars(test.spec, test.values)
			if test.hasError {
				assert.Equal(t, test.expectedError, err.Error())
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSpecSetVar(t *testing.T) {
	tests := []struct {
		description string
		spec        *ebpf.CollectionSpec
		name        string
		value       interface{}
		err         string
	}{
		{
			description: "variable found and set successfully",
			spec: &ebpf.CollectionSpec{
				Variables: map[string]*ebpf.VariableSpec{
					"foo":  {},
					"bar":  {},
					"test": {},
				},
			},
			name:  "foo",
			value: "test",
			err:   "setting \"foo\" variable: marshaling value : string doesn't marshal to 0 bytes",
		},
		{
			description: "variable not found",
			spec: &ebpf.CollectionSpec{
				Variables: map[string]*ebpf.VariableSpec{
					"bar":  {},
					"test": {},
				},
			},
			name:  "tests",
			value: "test",
			err:   "variable \"tests\" not found on ebpf spec: file does not exist",
		},
	}

	for _, test := range tests {
		t.Run(test.description, func(t *testing.T) {
			err := SpecSetVar(test.spec, test.name, test.value)
			assert.Contains(t, err.Error(), test.err)
		})
	}
}
