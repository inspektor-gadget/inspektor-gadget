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

type EllipsisType int

const (
	None   EllipsisType = iota // None simply cuts the text if it is too long
	End                        // End cuts an overflowing string one character before reaching the maximum width and adds an ellipsis ("…").
	Start                      // Start lets the overflowing string start with an ellipsis ("…") followed by the last X characters, where X is the maximum length - 1.
	Middle                     // Middle uses the first and last characters of an overflowing string, merging them in the middle with an ellipsis ("…").
)

const ellipsisRune = rune('…')

func (et EllipsisType) String() string {
	switch et {
	default:
		fallthrough
	case None:
		return "None"
	case End:
		return "End"
	case Start:
		return "Start"
	case Middle:
		return "Middle"
	}
}

func ShortenString(str string, maxLength int, ellipsisType EllipsisType) string {
	return string(Shorten([]rune(str), maxLength, ellipsisType))
}

func Shorten(rs []rune, maxLength int, ellipsisType EllipsisType) []rune {
	if maxLength <= 0 {
		return []rune{}
	}

	slen := len(rs)

	if slen <= maxLength {
		return rs
	}

	if maxLength <= 1 && ellipsisType != None {
		return []rune{ellipsisRune}
	}

	switch ellipsisType {
	default:
		fallthrough
	case None:
		return rs[:maxLength]
	case Start:
		return append([]rune{ellipsisRune}, rs[slen-maxLength+1:]...)
	case End:
		return append(rs[:maxLength-1], ellipsisRune)
	case Middle:
		mid := maxLength / 2
		end := mid
		if maxLength%2 == 0 {
			end -= 1
		}
		return append(append(rs[:mid], ellipsisRune), rs[slen-end:]...)
	}
}
