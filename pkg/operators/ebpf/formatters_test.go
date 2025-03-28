// Copyright 2025 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"testing"

	"github.com/cilium/ebpf/btf"
	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
)

func TestGetFormattersForEnums(t *testing.T) {
	type testCaseDatum struct {
		enum             *enum
		inputValue       uint64
		expectedOutput   string
		fieldName        string
		separator        string
		targetAnnotation string
		isMatch          bool
	}

	type testCase struct {
		name        string
		noOfMatches uint8
		data        []testCaseDatum
	}

	testCases := []testCase{
		{
			name:        "Single non-bitfield enum valid",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum1",
							Values: []btf.EnumValue{
								{Name: "A", Value: 1},
							},
							Signed: false,
						},
						memberName: "field1",
					},
					inputValue:       1,
					expectedOutput:   "A",
					fieldName:        "field1",
					targetAnnotation: "target1",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Single non-bitfield enum valid no target annotation",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum1",
							Values: []btf.EnumValue{
								{Name: "A", Value: 1},
							},
							Signed: false,
						},
						memberName: "field1_raw",
					},
					inputValue:     1,
					expectedOutput: "A",
					fieldName:      "field1",
					isMatch:        true,
				},
			},
		},
		{
			name:        "Single bitfield enum multiple flags",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_set",
							Values: []btf.EnumValue{
								{Name: "X", Value: 1},
								{Name: "Y", Value: 2},
							},
							Signed: false,
						},
						memberName: "field2",
					},
					inputValue:       3,
					expectedOutput:   "X|Y",
					fieldName:        "field2",
					separator:        "|",
					targetAnnotation: "target2",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Non-bitfield enum unknown",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_unknown",
							Values: []btf.EnumValue{
								{Name: "B", Value: 2},
								{Name: "C", Value: 3},
							},
							Signed: false,
						},
						memberName: "field3",
					},
					inputValue:       5,
					expectedOutput:   "UNKNOWN",
					fieldName:        "field3",
					targetAnnotation: "target3",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Non-bitfield enum with multiple similar values",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_similar",
							Values: []btf.EnumValue{
								{Name: "Alpha", Value: 5},
								{Name: "Beta", Value: 6},
								{Name: "Gamma", Value: 7},
							},
							Signed: false,
						},
						memberName: "field4",
					},
					inputValue:       6,
					expectedOutput:   "Beta",
					fieldName:        "field4",
					targetAnnotation: "target4",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Bitfield enum no flags set",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_set",
							Values: []btf.EnumValue{
								{Name: "FLAG1", Value: 1},
								{Name: "FLAG2", Value: 2},
							},
							Signed: false,
						},
						memberName: "field5",
					},
					inputValue:       0,
					expectedOutput:   "",
					fieldName:        "field5",
					separator:        "|",
					targetAnnotation: "target5",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Bitfield enum custom separator",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_custom_set",
							Values: []btf.EnumValue{
								{Name: "FLAG1", Value: 1},
								{Name: "FLAG2", Value: 2},
							},
							Signed: false,
						},
						memberName: "field6",
					},
					inputValue:       3,
					expectedOutput:   "FLAG1, FLAG2",
					fieldName:        "field6",
					separator:        ", ",
					targetAnnotation: "target6",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Multiple enums, first non-match then match",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_unknown",
							Values: []btf.EnumValue{
								{Name: "Nope", Value: 2},
							},
							Signed: false,
						},
						memberName: "nonmatch_field7a",
					},
					inputValue:       1,
					expectedOutput:   "UNKNOWN",
					fieldName:        "field7a",
					targetAnnotation: "target7a",
					isMatch:          false,
				},
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_match",
							Values: []btf.EnumValue{
								{Name: "Match", Value: 1},
							},
							Signed: false,
						},
						memberName: "field7b",
					},
					inputValue:       1,
					expectedOutput:   "Match",
					fieldName:        "field7b",
					targetAnnotation: "target7b",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Multiple non-bitfield enums both matching",
			noOfMatches: 2,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_first",
							Values: []btf.EnumValue{
								{Name: "First", Value: 1},
							},
							Signed: false,
						},
						memberName: "field8a",
					},
					inputValue:       1,
					expectedOutput:   "First",
					fieldName:        "field8a",
					targetAnnotation: "target8a",
					isMatch:          true,
				},
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_second",
							Values: []btf.EnumValue{
								{Name: "Second", Value: 1},
							},
							Signed: false,
						},
						memberName: "field8b",
					},
					inputValue:       1,
					expectedOutput:   "Second",
					fieldName:        "field8b",
					targetAnnotation: "target8b",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Non-bitfield then bitfield enum, bitfield wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_plain",
							Values: []btf.EnumValue{
								{Name: "Plain", Value: 1},
							},
							Signed: false,
						},
						memberName: "nonmatch_field9",
					},
					inputValue:       1,
					fieldName:        "field9",
					targetAnnotation: "target9a",
					isMatch:          false,
				},
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_set",
							Values: []btf.EnumValue{
								{Name: "BitOne", Value: 1},
								{Name: "BitTwo", Value: 2},
							},
							Signed: false,
						},
						memberName: "field10",
					},
					inputValue:       1,
					expectedOutput:   "BitOne",
					fieldName:        "field10",
					separator:        "|",
					targetAnnotation: "target9b",
					isMatch:          true,
				},
			},
		},
		{
			name:        "Multiple bitfield enums, last wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_set_first",
							Values: []btf.EnumValue{
								{Name: "FirstFlag", Value: 1},
							},
							Signed: false,
						},
						memberName: "nonmatch_field10a",
					},
					inputValue:       1,
					expectedOutput:   "FirstFlag",
					fieldName:        "field10a",
					separator:        "|",
					targetAnnotation: "target10a",
					isMatch:          false,
				},
				{
					enum: &enum{
						Enum: &btf.Enum{
							Name: "enum_set_second",
							Values: []btf.EnumValue{
								{Name: "SecondFlag", Value: 1},
								{Name: "ExtraFlag", Value: 2},
							},
							Signed: false,
						},
						memberName: "field10b",
					},
					inputValue:       1,
					expectedOutput:   "SecondFlag",
					fieldName:        "field10b",
					separator:        "|",
					targetAnnotation: "target10b",
					isMatch:          true,
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ds, _ := datasource.New(datasource.TypeSingle, "formatters")
			fas := make(map[string]datasource.FieldAccessor)

			for _, test := range tc.data {
				var fn string
				if test.targetAnnotation != "" {
					fn = test.fieldName
				} else {
					fn = test.fieldName + "_raw"
				}

				in, err := ds.AddField(fn, api.Kind_Uint64)
				require.NoError(t, err)
				require.NotNil(t, in)
				if test.separator != "" {
					in.AddAnnotation(enumBitfieldSeparatorAnnotation, test.separator)
				}
				if test.targetAnnotation != "" {
					in.AddAnnotation(enumTargetNameAnnotation, test.targetAnnotation)
				}
				fas[test.fieldName] = in
			}

			lg := logger.DefaultLogger()

			var enums []*enum
			for _, test := range tc.data {
				enums = append(enums, test.enum)
			}
			formatters, err := getFormattersForEnums(enums, ds, nil, lg)
			require.NoError(t, err)
			require.Len(t, formatters, int(tc.noOfMatches))

			formattersIndex := 0
			for _, test := range tc.data {
				if !test.isMatch {
					continue
				}
				data, _ := ds.NewPacketSingle()
				in := fas[test.fieldName]
				in.PutUint64(data, test.inputValue)

				err = formatters[formattersIndex](ds, data)
				require.NoError(t, err)

				var out datasource.FieldAccessor
				if test.targetAnnotation != "" {
					out = ds.GetField(test.targetAnnotation)
				} else {
					out = ds.GetField(test.fieldName)
				}
				res, _ := out.String(data)
				require.Equal(t, test.expectedOutput, res)
				formattersIndex++
			}
		})
	}
}

func TestFetchAndFormatStackTrace(t *testing.T) {
	type testCase struct {
		name          string
		stackEntries  [ebpftypes.KernelPerfMaxStackDepth]uint64
		expectedTrace string
	}

	testCases := []testCase{
		{
			name: "Valid stack trace",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0xabcdef, 0x123456, 0x312414, 0,
			},
			expectedTrace: "[0]funcA; [1]funcB; [2]unknown; ",
		},
		{
			name: "Empty stack trace",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0, 0, 0, 0,
			},
			expectedTrace: "",
		},
		{
			name: "Single valid entry",
			stackEntries: [ebpftypes.KernelPerfMaxStackDepth]uint64{
				0xabcdef, 0, 0, 0,
			},
			expectedTrace: "[0]funcA; ",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Custom stack lookup function for this test case.
			stackLookup := func(key interface{}, valueOut interface{}) error {
				stack := valueOut.(*[ebpftypes.KernelPerfMaxStackDepth]uint64)
				*stack = tc.stackEntries
				return nil
			}

			result, err := fetchAndFormatStackTrace(42, stackLookup, lookupByInstructionPointer)
			require.NoError(t, err)
			require.Equal(t, tc.expectedTrace, result)
		})
	}
}

func lookupByInstructionPointer(addr uint64) string {
	switch addr {
	case 0xabcdef:
		return "funcA"
	case 0x123456:
		return "funcB"
	default:
		return "unknown"
	}
}
