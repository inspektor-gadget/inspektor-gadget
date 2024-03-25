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

package btfhelpers

import (
	"reflect"
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/assert"
)

var int32Type = &btf.Int{
	Encoding: btf.Signed,
	Size:     4,
	Name:     "int32",
}

func TestGetType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		typ           btf.Type
		expectedType  reflect.Type
		expectedNames []string
	}{
		{
			name: "int8",
			typ: &btf.Int{
				Encoding: btf.Signed,
				Size:     1,
				Name:     "int8",
			},
			expectedType:  reflect.TypeOf(int8(0)),
			expectedNames: []string{"int8"},
		},
		{
			name: "int16",
			typ: &btf.Int{
				Encoding: btf.Signed,
				Size:     2,
				Name:     "int16",
			},
			expectedType:  reflect.TypeOf(int16(0)),
			expectedNames: []string{"int16"},
		},
		{
			name: "int32",
			typ: &btf.Int{
				Encoding: btf.Signed,
				Size:     4,
				Name:     "int32",
			},
			expectedType:  reflect.TypeOf(int32(0)),
			expectedNames: []string{"int32"},
		},
		{
			name: "int64",
			typ: &btf.Int{
				Encoding: btf.Signed,
				Size:     8,
				Name:     "int64",
			},
			expectedType:  reflect.TypeOf(int64(0)),
			expectedNames: []string{"int64"},
		},
		{
			name: "uint8",
			typ: &btf.Int{
				Encoding: btf.Unsigned,
				Size:     1,
				Name:     "uint8",
			},
			expectedType:  reflect.TypeOf(uint8(0)),
			expectedNames: []string{"uint8"},
		},
		{
			name: "uint16",
			typ: &btf.Int{
				Encoding: btf.Unsigned,
				Size:     2,
				Name:     "uint16",
			},
			expectedType:  reflect.TypeOf(uint16(0)),
			expectedNames: []string{"uint16"},
		},
		{
			name: "uint32",
			typ: &btf.Int{
				Encoding: btf.Unsigned,
				Size:     4,
				Name:     "uint32",
			},
			expectedType:  reflect.TypeOf(uint32(0)),
			expectedNames: []string{"uint32"},
		},
		{
			name: "uint64",
			typ: &btf.Int{
				Encoding: btf.Unsigned,
				Size:     8,
				Name:     "uint64",
			},
			expectedType:  reflect.TypeOf(uint64(0)),
			expectedNames: []string{"uint64"},
		},
		{
			name: "bool",
			typ: &btf.Int{
				Encoding: btf.Bool,
				Size:     1,
				Name:     "bool",
			},
			expectedType:  reflect.TypeOf(false),
			expectedNames: []string{"bool"},
		},
		{
			name: "char",
			typ: &btf.Int{
				Encoding: btf.Char,
				Size:     1,
				Name:     "char",
			},
			expectedType:  reflect.TypeOf(uint8(0)),
			expectedNames: []string{"char"},
		},
		{
			name: "float32",
			typ: &btf.Float{
				Size: 4,
				Name: "float32",
			},
			expectedType:  reflect.TypeOf(float32(0)),
			expectedNames: []string{"float32"},
		},
		{
			name: "float64",
			typ: &btf.Float{
				Size: 8,
				Name: "float64",
			},
			expectedType:  reflect.TypeOf(float64(0)),
			expectedNames: []string{"float64"},
		},
		{
			name: "typedef",
			typ: &btf.Typedef{
				Type: &btf.Int{
					Encoding: btf.Signed,
					Size:     4,
					Name:     "int32",
				},
				Name: "typedef",
			},
			expectedType:  reflect.TypeOf(int32(0)),
			expectedNames: []string{"typedef", "int32"},
		},
		{
			name: "typedef typedef",
			typ: &btf.Typedef{
				Type: &btf.Typedef{
					Type: int32Type,
					Name: "typedef2",
				},
				Name: "typedef1",
			},
			expectedType:  reflect.TypeOf(int32(0)),
			expectedNames: []string{"typedef1", "typedef2", "int32"},
		},
		{
			name: "array",
			typ: &btf.Array{
				Type:   int32Type,
				Nelems: 10,
			},
			expectedType:  reflect.ArrayOf(10, reflect.TypeOf(int32(0))),
			expectedNames: []string{"int32"},
		},
		{
			name: "array of arrays",
			typ: &btf.Array{
				Type: &btf.Array{
					Type:   int32Type,
					Nelems: 10,
				},
				Nelems: 10,
			},
			expectedType:  nil,
			expectedNames: nil,
		},
		{
			name:          "unknown",
			typ:           &btf.Void{},
			expectedNames: []string{},
		},
		{
			name: "unnamed",
			typ: &btf.Int{
				Encoding: btf.Unsigned,
				Size:     2,
			},
			expectedType:  reflect.TypeOf(uint16(0)),
			expectedNames: []string{},
		},
		// TODO: checks structures
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			retTyp, retNames := GetType(tt.typ)
			assert.Equal(t, tt.expectedType, retTyp)
			assert.Equal(t, tt.expectedNames, retNames)
		})
	}
}

func TestGetUnderlyingType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		typDef       *btf.Typedef
		expectedType btf.Type
	}{
		{
			name: "typedef",
			typDef: &btf.Typedef{
				Type: int32Type,
				Name: "typedef",
			},
			expectedType: int32Type,
		},
		{
			name: "typedef typedef",
			typDef: &btf.Typedef{
				Type: &btf.Typedef{
					Type: int32Type,
					Name: "typedef",
				},
				Name: "typedef",
			},
			expectedType: int32Type,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			retTyp := GetUnderlyingType(tt.typDef)
			assert.Equal(t, tt.expectedType, retTyp)
		})
	}
}
