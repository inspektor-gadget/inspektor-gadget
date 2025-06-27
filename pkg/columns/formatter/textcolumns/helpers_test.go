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

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type mockColumn struct {
	calculatedWidth int
}

type mockFormatter struct {
	showColumns []mockColumn
	fillString  string
}

func (tf *mockFormatter) buildFillString() {
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

func TestBuildFillString(t *testing.T) {
	tests := []struct {
		name         string
		showColumns  []mockColumn
		expectedFill string
	}{
		{
			name:         "no columns",
			showColumns:  []mockColumn{},
			expectedFill: "",
		},
		{
			name: "single column",
			showColumns: []mockColumn{
				{calculatedWidth: 5},
			},
			expectedFill: "     ",
		},
		{
			name: "multiple columns, different widths",
			showColumns: []mockColumn{
				{calculatedWidth: 3},
				{calculatedWidth: 7},
				{calculatedWidth: 5},
			},
			expectedFill: "       ",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tf := &mockFormatter{
				showColumns: tt.showColumns,
			}
			tf.buildFillString()
			assert.Equal(t, tt.expectedFill, tf.fillString)
		})
	}
}
