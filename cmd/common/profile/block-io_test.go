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

package profile

import (
	"fmt"
	"regexp"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"
)

type stsTestCase struct {
	val      uint64
	valMax   uint64
	width    uint64
	expected string
}

func (testcase stsTestCase) ToString() string {
	return fmt.Sprintf("(%v/%v), width %v", testcase.val, testcase.valMax, testcase.width)
}

func validateStarsToString(testCase stsTestCase, t *testing.T) {
	str := starsToString(testCase.val, testCase.valMax, testCase.width)
	if str != testCase.expected {
		t.Fail()
	}
}

func TestStarsToString(t *testing.T) {
	t.Parallel()

	testCases := []stsTestCase{
		/* Behaviour on values on the boundary of a new "*" */
		{
			val:      0,
			valMax:   64,
			width:    4,
			expected: "    ",
		},
		{
			val:      1,
			valMax:   64,
			width:    4,
			expected: "    ",
		},
		{
			val:      15,
			valMax:   64,
			width:    4,
			expected: "    ",
		},
		{
			val:      16,
			valMax:   64,
			width:    4,
			expected: "*   ",
		},
		{
			val:      31,
			valMax:   64,
			width:    4,
			expected: "*   ",
		},
		{
			val:      32,
			valMax:   64,
			width:    4,
			expected: "**  ",
		},
		{
			val:      63,
			valMax:   64,
			width:    4,
			expected: "*** ",
		},
		{
			val:      64,
			valMax:   64,
			width:    4,
			expected: "****",
		},
		/* When val > valMax */
		{
			val:      100,
			valMax:   2,
			width:    4,
			expected: "****+",
		},
		/* width is not divisor of valMax */
		{
			val:      38,
			valMax:   64,
			width:    5,
			expected: "**   ",
		},
		{
			val:      39,
			valMax:   64,
			width:    5,
			expected: "***  ",
		},
		/* width 1 */
		{
			val:      63,
			valMax:   64,
			width:    1,
			expected: " ",
		},
		{
			val:      64,
			valMax:   64,
			width:    1,
			expected: "*",
		},
		/* width 0 */
		{
			val:      0,
			valMax:   64,
			width:    0,
			expected: "",
		},
		{
			val:      64,
			valMax:   64,
			width:    0,
			expected: "",
		},
		{
			val:      65,
			valMax:   64,
			width:    0,
			expected: "+",
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.ToString(), func(t *testing.T) {
			validateStarsToString(testCase, t)
		})
	}
}

func validateReportToString(report types.Report, t *testing.T) {
	result := reportToString(report)

	if len(report.Data) == 0 {
		require.Equal(t, result, "")
		return
	}

	lines := regexp.MustCompile("\r?\n").Split(result, -1)

	require.Equal(t, len(lines), len(report.Data)+2)
	regexHeader := regexp.MustCompile(fmt.Sprintf(`\s*%s\s+:\s+count\s+distribution`, report.ValType))
	require.True(t, regexHeader.MatchString(lines[0]))
	require.Equal(t, lines[len(lines)-1], "")

	regexData := regexp.MustCompile(`\s*(\d+)\s->\s(\d+)\s+:\s(\d+)\s+\|\**\s*\|`)

	for i, data := range report.Data {
		// The first line contains the header, therefore +1 to start at the data lines
		line := lines[i+1]
		parts := regexData.FindStringSubmatch(line)

		require.Equal(t, len(parts), 4)
		require.Equal(t, parts[0], line)
		require.Equal(t, parts[1], strconv.FormatUint(data.IntervalStart, 10))
		require.Equal(t, parts[2], strconv.FormatUint(data.IntervalEnd, 10))
		require.Equal(t, parts[3], strconv.FormatUint(data.Count, 10))
	}
}

func TestReportToString(t *testing.T) {
	testCases := []types.Report{
		{
			ValType: "TwoRows",
			Data: []types.Data{
				{Count: 4, IntervalStart: 0, IntervalEnd: 4},
				{Count: 2, IntervalStart: 5, IntervalEnd: 10},
			},
		},
		{
			ValType: "ManyRows",
			Data: []types.Data{
				{Count: 4, IntervalStart: 0, IntervalEnd: 4},
				{Count: 2, IntervalStart: 5, IntervalEnd: 10},
				{Count: 41, IntervalStart: 11, IntervalEnd: 11},
				{Count: 25, IntervalStart: 12, IntervalEnd: 100},
				{Count: 78, IntervalStart: 101, IntervalEnd: 105},
				{Count: 35, IntervalStart: 106, IntervalEnd: 109},
				{Count: 7, IntervalStart: 110, IntervalEnd: 100000},
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.ValType, func(t *testing.T) {
			validateReportToString(testCase, t)
		})
	}
}
