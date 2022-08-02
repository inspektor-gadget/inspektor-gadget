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
	"encoding/json"
	"fmt"
	"os"
	"strings"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

// BaseElement represent any element that needs to be transform into a requested
// format. For instance, it could be an event (for trace category) or  a report
// (for the profile/cpu gadget).
type BaseElement interface {
	any

	// The Go compiler does not support accessing a struct field x.f where x is
	// of type parameter type even if all types in the type parameter's type set
	// have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() *eventtypes.Event
}

// BaseParser is a base for a parser that implements the most common methods.
type BaseParser[E BaseElement] struct {
	// ColumnsWidth are the columns that can be configured to be printed with
	// the width to be used.
	ColumnsWidth map[string]int

	// SeparateWithTabs defines whether the columns has to be separated with the
	// width defined in ColumnsWidth (if false), or with tabs ignoring the width
	// defined in ColumnsWidth (if true).
	SeparateWithTabs bool

	// OutputConfig provides to the parser the flags that describes how to print
	// the gadget's output.
	OutputConfig *OutputConfig
}

func newBaseParser[E BaseElement](columnsWidth map[string]int, useTabs bool, outputConfig *OutputConfig) BaseParser[E] {
	return BaseParser[E]{
		ColumnsWidth:     columnsWidth,
		SeparateWithTabs: useTabs,
		OutputConfig:     outputConfig,
	}
}

// NewBaseTabParser returns a BaseParser configured to print columns separated
// by tabs.
func NewBaseTabParser[E BaseElement](availableColumns []string, outputConfig *OutputConfig) BaseParser[E] {
	// Adapt an availableColumns slice to be passed to NewBaseParser. Given that
	// NewBaseParser will be called with useTabs=true, the columns will be
	// separated by tabs and the width values will be just ignored. Therefore,
	// the width values used here don't matter at all.
	adaptedColumns := make(map[string]int, len(availableColumns))
	for _, v := range availableColumns {
		adaptedColumns[v] = 0
	}

	return newBaseParser[E](adaptedColumns, true, outputConfig)
}

// NewBaseWidthParser returns a BaseParser configured to print columns separated
// by their predefined with.
func NewBaseWidthParser[E BaseElement](columnsWidth map[string]int, outputConfig *OutputConfig) BaseParser[E] {
	return newBaseParser[E](columnsWidth, false, outputConfig)
}

func (p *BaseParser[E]) BuildColumnsHeader() string {
	var sb strings.Builder

	for _, col := range p.OutputConfig.CustomColumns {
		width, ok := p.ColumnsWidth[col]
		if !ok {
			// Ignore invalid columns
			continue
		}

		if p.SeparateWithTabs {
			// In this case, the generated header is expected to be printed
			// using a tabwriter. See example of usage on the snapshot gadgets
			// or the list-containers command of local-gadget.
			sb.WriteString(strings.ToUpper(col) + "\t")
		} else {
			// Additional space is needed when field is larger than the
			// predefined ColumnsWidth, see TransformEvent methods.
			sb.WriteString(fmt.Sprintf("%*s ", width, strings.ToUpper(col)))
		}
	}

	return sb.String()
}

func (p *BaseParser[E]) Transform(element *E, toColumns func(*E) string) string {
	// For non event-based gadgets, or gadgets that want to manage these special
	// cases by themselves, GetBaseEvent() simply needs to return nil.
	baseEvent := (*element).GetBaseEvent()
	if baseEvent != nil && baseEvent.Type != eventtypes.NORMAL {
		ManageSpecialEvent(baseEvent, p.OutputConfig.Verbose)
		return ""
	}

	switch p.OutputConfig.OutputMode {
	case OutputModeJSON:
		b, err := json.Marshal(element)
		if err != nil {
			fmt.Fprint(os.Stderr, fmt.Sprint(WrapInErrMarshalOutput(err)))
			return ""
		}

		return string(b)
	case OutputModeColumns:
		fallthrough
	case OutputModeCustomColumns:
		return toColumns(element)
	}

	return ""
}

func (p *BaseParser[E]) GetOutputConfig() *OutputConfig {
	return p.OutputConfig
}

func GetKubernetesColumns() []string {
	return []string{
		"node",
		"namespace",
		"pod",
		"container",
	}
}
