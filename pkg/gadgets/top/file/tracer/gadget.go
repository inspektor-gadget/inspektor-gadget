// Copyright 2022-2023 The Inspektor Gadget authors
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

package tracer

import (
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "file"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTop
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTraceIntervals
}

func (g *GadgetDesc) Description() string {
	return "Periodically report read/write activity by file"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          types.AllFilesParam,
			Title:        "Show all files",
			DefaultValue: "false",
			Description:  "show regular files only vs. show all files", // TODO: clarify
			IsMandatory:  true,
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Stats](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Stats{}
}

func (g *GadgetDesc) SortByDefault() []string {
	return types.SortByDefault
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
