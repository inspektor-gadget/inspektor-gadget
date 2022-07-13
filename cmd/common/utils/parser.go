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

package utils

import (
	"fmt"
	"strings"
)

// BaseParser is a base for a TraceParser to reuse the shared fields and
// methods.
type BaseParser struct {
	ColumnsWidth map[string]int
	OutputConfig *OutputConfig
}

func (p *BaseParser) PrintColumnsHeader() {
	var sb strings.Builder

	for _, col := range p.OutputConfig.CustomColumns {
		if width, ok := p.ColumnsWidth[col]; ok {
			sb.WriteString(fmt.Sprintf("%*s", width, strings.ToUpper(col)))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	fmt.Println(sb.String())
}
