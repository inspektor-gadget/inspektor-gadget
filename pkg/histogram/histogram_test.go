// Copyright 2023 The Inspektor Gadget authors
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

package histogram

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHistogram_NewIntervalsFromExp2Slots(t *testing.T) {
	t.Parallel()

	const unit = UnitMicroseconds

	testTable := []struct {
		description string
		slots       []uint32
		expected    *Histogram
	}{
		{
			description: "Nil slots",
			slots:       nil,
			expected: &Histogram{
				Unit:      unit,
				Intervals: nil,
			},
		},
		{
			description: "Empty slots",
			slots:       []uint32{},
			expected: &Histogram{
				Unit:      unit,
				Intervals: nil,
			},
		},
		{
			description: "With 1 slot",
			slots:       []uint32{333},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 333, Start: 0, End: 1},
				},
			},
		},
		{
			description: "With 2 slots",
			slots:       []uint32{777, 555},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 777, Start: 0, End: 1},
					{Count: 555, Start: 2, End: 3},
				},
			},
		},
		{
			description: "With zero slots",
			slots:       []uint32{222, 0, 111},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 222, Start: 0, End: 1},
					{Count: 0, Start: 2, End: 3},
					{Count: 111, Start: 4, End: 7},
				},
			},
		},
		{
			description: "Zero at first slot",
			slots:       []uint32{0, 888, 0, 666},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 0, Start: 0, End: 1},
					{Count: 888, Start: 2, End: 3},
					{Count: 0, Start: 4, End: 7},
					{Count: 666, Start: 8, End: 15},
				},
			},
		},
		{
			description: "Multiple zeros at first slots",
			slots:       []uint32{0, 0, 0, 111},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 0, Start: 0, End: 1},
					{Count: 0, Start: 2, End: 3},
					{Count: 0, Start: 4, End: 7},
					{Count: 111, Start: 8, End: 15},
				},
			},
		},
		{
			description: "Multiple zeros at last slots",
			slots:       []uint32{0, 888, 0, 111, 0, 0, 0},
			expected: &Histogram{
				Unit: unit,
				Intervals: []Interval{
					{Count: 0, Start: 0, End: 1},
					{Count: 888, Start: 2, End: 3},
					{Count: 0, Start: 4, End: 7},
					{Count: 111, Start: 8, End: 15},
				},
			},
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()

			h := &Histogram{
				Unit:      unit,
				Intervals: NewIntervalsFromExp2Slots(test.slots),
			}
			require.Equal(t, test.expected, h, "creating histogram from exp2 slots")
		})
	}
}

func TestHistogram_String(t *testing.T) {
	t.Parallel()

	testTable := []struct {
		description string
		histogram   *Histogram
		expected    string
	}{
		{
			description: "Empty histogram",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: []Interval{},
			},
			expected: "",
		},
		{
			description: "With 1 slot value 1",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{1}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 1        |****************************************|\n",
		},
		{
			description: "With 1 slot value 55",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{55}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 55       |****************************************|\n",
		},
		{
			description: "scale",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{1, 2, 3}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 1        |*************                           |\n" +
				"         2 -> 3          : 2        |**************************              |\n" +
				"         4 -> 7          : 3        |****************************************|\n",
		},
		{
			description: "scale with empty slots",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{1, 0, 3}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 1        |*************                           |\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 3        |****************************************|\n",
		},
		{
			description: "scale with empty slots and same values 1",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{1, 0, 1}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 1        |****************************************|\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 1        |****************************************|\n",
		},
		{
			description: "scale with empty slots and same values 100",
			histogram: &Histogram{
				Unit:      UnitMicroseconds,
				Intervals: NewIntervalsFromExp2Slots([]uint32{100, 0, 100}),
			},
			expected: "" +
				"        µs               : count    distribution\n" +
				"         0 -> 1          : 100      |****************************************|\n" +
				"         2 -> 3          : 0        |                                        |\n" +
				"         4 -> 7          : 100      |****************************************|\n",
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()

			actual := test.histogram.String()
			require.Equal(t, test.expected, actual, "histogram string representation")
		})
	}
}
