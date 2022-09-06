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

package textcolumns

import "strings"

// buildFillString builds a string that has the length of the widest column; it is used to copy
// whitespace from, instead of generating it character by character all the time
func (tf *TextColumnsFormatter[T]) buildFillString() {
	maxLength := 0
	for _, column := range tf.showColumns {
		if column.calculatedWidth > maxLength {
			maxLength = column.calculatedWidth
		}
	}

	var s strings.Builder
	for i := 0; i < maxLength; i++ {
		s.WriteString(" ")
	}
	tf.fillString = s.String()
}
