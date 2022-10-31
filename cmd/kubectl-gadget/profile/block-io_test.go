package profile

import (
	"fmt"
	"testing"
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
