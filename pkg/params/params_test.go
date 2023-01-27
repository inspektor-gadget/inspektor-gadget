// Copyright 2022-2023 The Inspektor Gadget authors
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

package params

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestParamAs(t *testing.T) {
	type test struct {
		name     string
		value    string
		expected any
		getter   func(*Param) any
	}

	tests := []test{
		{
			name:     "Float32()",
			value:    "-20.123",
			expected: float32(-20.123),
			getter:   func(p *Param) any { return p.AsFloat32() },
		},
		{
			name:     "Floa64()",
			value:    "-20.123456",
			expected: float64(-20.123456),
			getter:   func(p *Param) any { return p.AsFloat64() },
		},
		{
			name:     "Int()",
			value:    "-20",
			expected: int(-20),
			getter:   func(p *Param) any { return p.AsInt() },
		},
		{
			name:     "Int8()",
			value:    "-111",
			expected: int8(-111),
			getter:   func(p *Param) any { return p.AsInt8() },
		},
		{
			name:     "Int16()",
			value:    "-5555",
			expected: int16(-5555),
			getter:   func(p *Param) any { return p.AsInt16() },
		},
		{
			name:     "Int32()",
			value:    "-33333",
			expected: int32(-33333),
			getter:   func(p *Param) any { return p.AsInt32() },
		},
		{
			name:     "Int64()",
			value:    "-2222222222",
			expected: int64(-2222222222),
			getter:   func(p *Param) any { return p.AsInt64() },
		},
		{
			name:     "Uint()",
			value:    "20",
			expected: uint(20),
			getter:   func(p *Param) any { return p.AsUint() },
		},
		{
			name:     "Uint8()",
			value:    "111",
			expected: uint8(111),
			getter:   func(p *Param) any { return p.AsUint8() },
		},
		{
			name:     "Uint16()",
			value:    "5555",
			expected: uint16(5555),
			getter:   func(p *Param) any { return p.AsUint16() },
		},
		{
			name:     "Uint32()",
			value:    "33333",
			expected: uint32(33333),
			getter:   func(p *Param) any { return p.AsUint32() },
		},
		{
			name:     "Uint64()",
			value:    "2222222222",
			expected: uint64(2222222222),
			getter:   func(p *Param) any { return p.AsUint64() },
		},
		{
			name:     "String()",
			value:    "eW91J3JlIGN1cmlvdXM=",
			expected: string("eW91J3JlIGN1cmlvdXM="),
			getter:   func(p *Param) any { return p.AsString() },
		},
		{
			name:     "StringSlice()",
			value:    "foo,bar,zas",
			expected: []string{"foo", "bar", "zas"},
			getter:   func(p *Param) any { return p.AsStringSlice() },
		},
		{
			name:     "StringSlice()_Empty",
			value:    "",
			expected: []string{},
			getter:   func(p *Param) any { return p.AsStringSlice() },
		},
		{
			name:     "Bool()_true",
			value:    "true",
			expected: bool(true),
			getter:   func(p *Param) any { return p.AsBool() },
		},
		{
			name:     "Bool()_false",
			value:    "false",
			expected: bool(false),
			getter:   func(p *Param) any { return p.AsBool() },
		},
		{
			name:     "Uint16Slice()",
			value:    "7777,8888,9999",
			expected: []uint16{7777, 8888, 9999},
			getter:   func(p *Param) any { return p.AsUint16Slice() },
		},
		{
			name:     "Uint16Slice()_empty",
			value:    "",
			expected: []uint16{},
			getter:   func(p *Param) any { return p.AsUint16Slice() },
		},
		{
			name:     "Uint64Slice()",
			value:    "7777,8888,9999",
			expected: []uint64{7777, 8888, 9999},
			getter:   func(p *Param) any { return p.AsUint64Slice() },
		},
		{
			name:     "Uint64Slice()_empty",
			value:    "",
			expected: []uint64{},
			getter:   func(p *Param) any { return p.AsUint64Slice() },
		},
		{
			name:     "Int64Slice()",
			value:    "-7777,-8888,9999",
			expected: []int64{-7777, -8888, 9999},
			getter:   func(p *Param) any { return p.AsInt64Slice() },
		},
		{
			name:     "Uint64Slice()_empty",
			value:    "",
			expected: []int64{},
			getter:   func(p *Param) any { return p.AsInt64Slice() },
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			p := &Param{
				ParamDesc: &ParamDesc{},
				value:     test.value,
			}

			require.Equal(t, test.expected, test.getter(p))
		})
	}
}

func TestParamsValidators(t *testing.T) {
	type test struct {
		name          string
		desc          *ParamDesc
		value         string
		expectedError bool
	}

	tests := []test{
		{
			name:          "novalidation",
			desc:          &ParamDesc{},
			value:         "for,bar,yes,20.33",
			expectedError: false,
		},
		{
			name:          "novalidation_empty_str",
			desc:          &ParamDesc{},
			value:         "",
			expectedError: false,
		},
		{
			name: "IsMandatory_true_error",
			desc: &ParamDesc{
				IsMandatory: true,
			},
			value:         "",
			expectedError: true,
		},
		{
			name: "IsMandatory_true_no_error",
			desc: &ParamDesc{
				IsMandatory: true,
			},
			value:         "foo",
			expectedError: false,
		},
		{
			name: "PossibleValues_2_no_error",
			desc: &ParamDesc{
				PossibleValues: []string{"foo", "bar"},
			},
			value:         "foo",
			expectedError: false,
		},
		{
			name: "PossibleValues_2_error",
			desc: &ParamDesc{
				PossibleValues: []string{"foo", "bar"},
			},
			value:         "zas",
			expectedError: true,
		},
		{
			name: "TypeHint_int_no_error",
			desc: &ParamDesc{
				TypeHint: TypeInt,
			},
			value:         "-256",
			expectedError: false,
		},
		{
			name: "TypeHint_int_error",
			desc: &ParamDesc{
				TypeHint: TypeInt,
			},
			value:         "zas",
			expectedError: true,
		},
		{
			name: "TypeHint_uint_no_error",
			desc: &ParamDesc{
				TypeHint: TypeUint,
			},
			value:         "256",
			expectedError: false,
		},
		{
			name: "TypeHint_uint_error_string",
			desc: &ParamDesc{
				TypeHint: TypeUint,
			},
			value:         "zas",
			expectedError: true,
		},
		{
			name: "TypeHint_uint_error_negative",
			desc: &ParamDesc{
				TypeHint: TypeUint,
			},
			value:         "-256",
			expectedError: true,
		},
		{
			name: "TypeHint_bool_no_error_false",
			desc: &ParamDesc{
				TypeHint: TypeBool,
			},
			value:         "false",
			expectedError: false,
		},
		{
			name: "TypeHint_bool_no_error_true",
			desc: &ParamDesc{
				TypeHint: TypeBool,
			},
			value:         "true",
			expectedError: false,
		},
		{
			name: "TypeHint_bool_error",
			desc: &ParamDesc{
				TypeHint: TypeBool,
			},
			value:         "zas",
			expectedError: true,
		},
		{
			name: "Validator_error",
			desc: &ParamDesc{
				Validator: func(string) error { return errors.New("error") },
			},
			value:         "zas",
			expectedError: true,
		},
		{
			name: "Validator_no_error",
			desc: &ParamDesc{
				Validator: func(string) error { return nil },
			},
			value:         "zas",
			expectedError: false,
		},
		{
			name: "IsMandatory_and_Validator",
			desc: &ParamDesc{
				IsMandatory: true,
				Validator:   func(string) error { return nil },
			},
			value:         "",
			expectedError: true,
		},
		{
			name: "IsMandatory_and_PossibleValues",
			desc: &ParamDesc{
				IsMandatory:    true,
				PossibleValues: []string{"", "foo", "bar"},
			},
			value:         "",
			expectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			p := test.desc.ToParam()

			err := p.Set(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestParamDefaultValue(t *testing.T) {
	pd := ParamDesc{
		DefaultValue: "foo",
	}

	param := pd.ToParam()
	require.Equal(t, "foo", param.String())
	param.Set("bar")
	require.Equal(t, "bar", param.String())
}
