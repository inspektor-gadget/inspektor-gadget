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

package ellipsis

import (
	"fmt"
	"testing"
)

func TestEllipsis(t *testing.T) {
	type ellipsisTest struct {
		Input     string
		MaxLength int
		Type      EllipsisType
		Result    string
	}

	ellipsisTests := []ellipsisTest{
		{
			Input:     "Demo",
			MaxLength: 8,
			Type:      None,
			Result:    "Demo",
		},
		{
			Input:     "D",
			MaxLength: 1,
			Type:      None,
			Result:    "D",
		},
		{
			Input:     "Demo1234",
			MaxLength: 4,
			Type:      None,
			Result:    "Demo",
		},
		{
			Input:     "Demo1234",
			MaxLength: 4,
			Type:      End,
			Result:    "Dem…",
		},
		{
			Input:     "Demo1234",
			MaxLength: 4,
			Type:      Start,
			Result:    "…234",
		},
		{
			Input:     "Demo1234",
			MaxLength: 4,
			Type:      Middle,
			Result:    "De…4",
		},
		{
			Input:     "Demo1234",
			MaxLength: 5,
			Type:      Middle,
			Result:    "De…34",
		},
		{
			Input:     "Demo🖐🖐🖐🖐",
			MaxLength: 8,
			Type:      None,
			Result:    "Demo🖐🖐🖐🖐",
		},
		{
			Input:     "A",
			MaxLength: 1,
			Type:      None,
			Result:    "A",
		},
		{
			Input:     "Demo",
			MaxLength: 0,
			Type:      None,
			Result:    "",
		},
		{
			Input:     "Demo",
			MaxLength: 1,
			Type:      None,
			Result:    "D",
		},
		{
			Input:     "Demo",
			MaxLength: 1,
			Type:      Start,
			Result:    "…",
		},
		{
			Input:     "Demo",
			MaxLength: 1,
			Type:      End,
			Result:    "…",
		},
		{
			Input:     "Demo",
			MaxLength: 1,
			Type:      Middle,
			Result:    "…",
		},
		{
			Input:     "Exact",
			MaxLength: 5,
			Type:      None,
			Result:    "Exact",
		},
		{
			Input:     "Exact",
			MaxLength: 5,
			Type:      Start,
			Result:    "Exact",
		},
		{
			Input:     "Exact",
			MaxLength: 5,
			Type:      End,
			Result:    "Exact",
		},
		{
			Input:     "Exact",
			MaxLength: 5,
			Type:      Middle,
			Result:    "Exact",
		},
		{
			Input:     "Demo",
			MaxLength: 3,
			Type:      -1,
			Result:    "Dem",
		},
		{
			Input:     "",
			MaxLength: 5,
			Type:      None,
			Result:    "",
		},
		{
			Input:     "",
			MaxLength: 5,
			Type:      Start,
			Result:    "",
		},
		{
			Input:     "",
			MaxLength: 5,
			Type:      End,
			Result:    "",
		},
		{
			Input:     "",
			MaxLength: 5,
			Type:      Middle,
			Result:    "",
		},
		{
			Input:     "Demo",
			MaxLength: 4,
			Type:      None,
			Result:    "Demo",
		},
	}

	for _, test := range ellipsisTests {
		t.Run(fmt.Sprintf("%s_%d@%s", test.Input, test.MaxLength, test.Type.String()), func(t *testing.T) {
			if res := Shorten([]rune(test.Input), test.MaxLength, test.Type); string(res) != test.Result {
				t.Errorf("%q (%d): got %q, expected %q", test.Input, test.MaxLength, res, test.Result)
			}
		})
	}
}

func FuzzEllipsis(f *testing.F) {
	f.Add("inputString", 5)
	f.Fuzz(func(t *testing.T, inputString string, maxLength int) {
		correctedLength := maxLength
		if maxLength < 0 {
			correctedLength = 0
		}
		if out := Shorten([]rune(inputString), maxLength, None); len(out) > correctedLength {
			t.Errorf("None of %q (%d): wrong output %q of length %d", inputString, maxLength, out, len(out))
		}
		if out := Shorten([]rune(inputString), maxLength, End); len(out) > correctedLength {
			t.Errorf("End of %q (%d): wrong output %q of length %d", inputString, maxLength, out, len(out))
		}
		if out := Shorten([]rune(inputString), maxLength, Start); len(out) > correctedLength {
			t.Errorf("Start of %q (%d): wrong output %q of length %d", inputString, maxLength, out, len(out))
		}
		if out := Shorten([]rune(inputString), maxLength, Middle); len(out) > correctedLength {
			t.Errorf("Middle of %q (%d): wrong output %q of length %d", inputString, maxLength, out, len(out))
		}
	})
}
