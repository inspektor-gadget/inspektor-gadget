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

package gadgets

import (
	"strings"

	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamInterval = "interval"
	ParamSortBy   = "sort-by"
	ParamMaxRows  = "max-rows"
)

// DefaultSort can be implemented in addition to the Gadget interface, to specify the default sorting columns
type DefaultSort interface {
	SortByDefault() []string
}

// GadgetParams returns params specific to the gadgets' type - for example, it returns
// sort-by parameter and max rows for gadgets with sortable results, and interval parameters
// when the gadget is to be called periodically
func GadgetParams(gadget Gadget, columns columnhelpers.Columns) params.Params {
	p := params.Params{}
	if gadget.Type().IsPeriodic() {
		p.Add(IntervalParams()...)
	}
	if gadget.Type().CanSort() {
		p.Add(SortableParams(gadget, columns)...)
	}
	return p
}

func IntervalParams() params.Params {
	return params.Params{
		{
			Key:          ParamInterval,
			Title:        "Interval",
			DefaultValue: "1",
			TypeHint:     params.TypeUint,
			Description:  "Interval (in Seconds)",
		},
	}
}

func SortableParams(gadget Gadget, columns columnhelpers.Columns) params.Params {
	if columns == nil {
		return nil
	}

	var defaultSort []string
	if sortInterface, ok := gadget.(DefaultSort); ok {
		defaultSort = sortInterface.SortByDefault()
	}

	return params.Params{
		{
			Key:          ParamMaxRows,
			Title:        "Max Rows",
			DefaultValue: "50",
			TypeHint:     params.TypeInt,
			Description:  "Maximum number of rows to return",
		},
		{
			Key:          ParamSortBy,
			Title:        "Sort By",
			DefaultValue: strings.Join(defaultSort, ","),
			Description:  "Sort by columns. Join multiple columns with ','. Prefix a column with '-' to sort in descending order.",
		},
	}
}
