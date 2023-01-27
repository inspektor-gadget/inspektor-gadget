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
	"fmt"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateIntUint(t *testing.T) {
	type test struct {
		name          string
		bitSize       int
		value         string
		expectedError bool
		validateFn    func(bitsize int) func(string) error
	}

	tests := []test{}

	bitSizes := []int{8, 16, 32, 64}

	// ValidateInt
	for _, bitSize := range bitSizes {
		// test max and min numbers allowed
		tests = append(tests, test{
			name:          fmt.Sprintf("int%d_max", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatInt(1<<(bitSize-1)-1, 10),
			expectedError: false,
			validateFn:    ValidateInt,
		})

		tests = append(tests, test{
			name:          fmt.Sprintf("int%d_min", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatInt(-(1 << (bitSize - 1)), 10),
			expectedError: false,
			validateFn:    ValidateInt,
		})

		// test offset by one numbers
		if bitSize == 64 {
			tests = append(tests, test{
				name:          fmt.Sprintf("int%d_max+1", bitSize),
				bitSize:       bitSize,
				value:         "9223372036854775808", // 2^63
				expectedError: true,
				validateFn:    ValidateInt,
			})

			tests = append(tests, test{
				name:          fmt.Sprintf("int%d_min-1", bitSize),
				bitSize:       bitSize,
				value:         "-9223372036854775809", // -2^63 - 1
				expectedError: true,
				validateFn:    ValidateInt,
			})
			break
		}

		tests = append(tests, test{
			name:          fmt.Sprintf("int%d_max+1", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatInt(1<<(bitSize-1), 10),
			expectedError: true,
			validateFn:    ValidateInt,
		})

		tests = append(tests, test{
			name:          fmt.Sprintf("int%d_min-1", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatInt(-(1<<(bitSize-1))-1, 10),
			expectedError: true,
			validateFn:    ValidateInt,
		})
	}

	// ValidateUint
	for _, bitSize := range bitSizes {
		// test max numbers allowed
		tests = append(tests, test{
			name:          fmt.Sprintf("uint%d_max", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatUint(1<<(bitSize)-1, 10),
			expectedError: false,
			validateFn:    ValidateUint,
		})

		// test offset by one numbers
		if bitSize == 64 {
			// we need to hardcode this one, otherwise it'll overflow
			tests = append(tests, test{
				name:          fmt.Sprintf("uint%d_max+1", bitSize),
				bitSize:       bitSize,
				value:         "18446744073709551616", // 2^64 + 1
				expectedError: true,
				validateFn:    ValidateUint,
			})
			break
		}

		tests = append(tests, test{
			name:          fmt.Sprintf("uint%d_max+1", bitSize),
			bitSize:       bitSize,
			value:         strconv.FormatUint(1<<(bitSize), 10),
			expectedError: true,
			validateFn:    ValidateUint,
		})
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			fmt.Printf("set value: %s\n", test.value)

			err := test.validateFn(test.bitSize)(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidateBool(t *testing.T) {
	type test struct {
		name          string
		value         string
		expectedError bool
	}

	tests := []test{
		{
			name:          "true_no_error",
			value:         "true",
			expectedError: false,
		},
		{
			name:          "false_no_error",
			value:         "false",
			expectedError: false,
		},
		{
			name:          "bad_input_foo",
			value:         "foo",
			expectedError: true,
		},
		{
			name:          "bad_input_0",
			value:         "0",
			expectedError: true,
		},
		{
			name:          "bad_input_1",
			value:         "1",
			expectedError: true,
		},
		{
			name:          "bad_input_empty",
			value:         "",
			expectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := ValidateBool(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidateIntRange(t *testing.T) {
	type test struct {
		min           int64
		max           int64
		value         string
		expectedError bool
	}

	tests := []test{
		{
			min:           -10,
			max:           10,
			value:         "10",
			expectedError: false,
		},
		{
			min:           -10,
			max:           10,
			value:         "11",
			expectedError: true,
		},
		{
			min:           -10,
			max:           10,
			value:         "-10",
			expectedError: false,
		},
		{
			min:           -10,
			max:           10,
			value:         "-11",
			expectedError: true,
		},
		{
			min:           -10,
			max:           10,
			value:         "foo",
			expectedError: true,
		},
		{
			min:           int64(-9223372036854775808),
			max:           int64(9223372036854775808 - 1),
			value:         "9223372036854775808", // 2^63
			expectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(fmt.Sprintf("min%d_max%d_error_%t", test.min, test.max, test.expectedError), func(t *testing.T) {
			err := ValidateIntRange(test.min, test.max)(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidateUintRange(t *testing.T) {
	type test struct {
		min           uint64
		max           uint64
		value         string
		expectedError bool
	}

	tests := []test{
		{
			min:           10,
			max:           20,
			value:         "20",
			expectedError: false,
		},
		{
			min:           10,
			max:           20,
			value:         "21",
			expectedError: true,
		},
		{
			min:           10,
			max:           20,
			value:         "10",
			expectedError: false,
		},
		{
			min:           10,
			max:           20,
			value:         "9",
			expectedError: true,
		},
		{
			min:           10,
			max:           20,
			value:         "foo",
			expectedError: true,
		},
		{
			min:           0,
			max:           uint64(18446744073709551616 - 1),
			value:         "18446744073709551616", // 2^64
			expectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		name := fmt.Sprintf("min%d_max%d_error_%t", test.min, test.max, test.expectedError)
		t.Run(name, func(t *testing.T) {
			err := ValidateUintRange(test.min, test.max)(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}

func TestValidateSlice(t *testing.T) {
	type test struct {
		name          string
		value         string
		validator     func(string) error
		expectedError bool
	}

	noErrFn := func(string) error { return nil }
	errFn := func(string) error { return errors.New("error") }

	tests := []test{
		{
			name:          "empty_slice_no_error",
			value:         "",
			validator:     noErrFn,
			expectedError: false,
		},
		{
			name:          "empty_slice_error",
			value:         "",
			validator:     errFn,
			expectedError: true,
		},
		{
			name:          "slice_with_2_elements_no_error",
			value:         "foo,bar",
			validator:     noErrFn,
			expectedError: false,
		},
		{
			name:          "slice_with_2_elements_no_error",
			value:         "foo,bar",
			validator:     errFn,
			expectedError: true,
		},
		{
			name:  "slice_with_2_elements_custom_err_func",
			value: "foo,bar",
			validator: func(s string) error {
				if s == "bar" {
					return errors.New("error")
				}

				return nil
			},
			expectedError: true,
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			err := ValidateSlice(test.validator)(test.value)
			if test.expectedError {
				require.Error(t, err)
			} else {
				require.Nil(t, err)
			}
		})
	}
}
