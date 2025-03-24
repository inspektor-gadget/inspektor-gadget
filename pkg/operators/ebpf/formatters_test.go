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
	nonBitfieldEnum := constructNValuedEnum([]string{"A", "B", "C"}, "field1", false)
	bitfieldEnum := constructNValuedEnum([]string{"A", "B", "C"}, "field1", true)

	type testCaseDatum struct {
		enum                    *enum
		inputValue              uint64
		expectedOutput          string
		expectedTargetFieldName string
		separator               string
		targetAnnotation        string
		isMatch                 bool
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
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Single non-bitfield enum valid no target annotation",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"A", "B", "C"}, "field1_raw", false),
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Single bitfield enum multiple flags",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              3,
					expectedOutput:          "A|B|C",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield enum unknown",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              5,
					expectedOutput:          "UNKNOWN",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield enum with multiple similar values",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Bitfield enum no flags set",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              0,
					expectedOutput:          "",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Bitfield enum custom separator",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    bitfieldEnum,
					inputValue:              3,
					expectedOutput:          "A, B, C",
					expectedTargetFieldName: "field1",
					separator:               ", ",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple enums, first non-match then match",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					expectedTargetFieldName: "nonmatch_field1",
					targetAnnotation:        "target1",
					isMatch:                 false,
				},
				{
					enum:                    constructNValuedEnum([]string{"Match"}, "field2", false),
					inputValue:              1,
					expectedOutput:          "Match",
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple non-bitfield enums both matching",
			noOfMatches: 2,
			data: []testCaseDatum{
				{
					enum:                    nonBitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
				{
					enum:                    constructNValuedEnum([]string{"Second"}, "field2", false),
					inputValue:              1,
					expectedOutput:          "Second",
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Non-bitfield then bitfield enum, bitfield wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"Plain"}, "nonmatch_field2", false),
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 false,
				},
				{
					enum:                    bitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
				},
			},
		},
		{
			name:        "Multiple bitfield enums, last wins",
			noOfMatches: 1,
			data: []testCaseDatum{
				{
					enum:                    constructNValuedEnum([]string{"FirstFlag"}, "nonmatch_field2", true),
					expectedTargetFieldName: "field2",
					targetAnnotation:        "target2",
					isMatch:                 false,
				},
				{
					enum:                    bitfieldEnum,
					inputValue:              1,
					expectedOutput:          "A",
					expectedTargetFieldName: "field1",
					separator:               "|",
					targetAnnotation:        "target1",
					isMatch:                 true,
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
					fn = test.expectedTargetFieldName
				} else {
					fn = test.expectedTargetFieldName + "_raw"
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
				fas[test.expectedTargetFieldName] = in
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
				in := fas[test.expectedTargetFieldName]
				in.PutUint64(data, test.inputValue)

				err = formatters[formattersIndex](ds, data)
				require.NoError(t, err)

				var out datasource.FieldAccessor
				if test.targetAnnotation != "" {
					out = ds.GetField(test.targetAnnotation)
				} else {
					out = ds.GetField(test.expectedTargetFieldName)
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

func constructNValuedEnum(keys []string, memberName string, isBitField bool) *enum {
	var vals []btf.EnumValue
	for i, v := range keys {
		vals = append(vals, btf.EnumValue{Name: v, Value: uint64(i + 1)})
	}

	name := "testenum"
	if isBitField {
		name += "_set"
	}
	return &enum{
		Enum: &btf.Enum{
			Name:   name,
			Values: vals,
			Signed: false,
		},
		memberName: memberName,
	}
}
