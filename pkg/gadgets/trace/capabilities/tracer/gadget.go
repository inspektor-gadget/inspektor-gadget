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
	"github.com/inspektor-gadget/inspektor-gadget/internal/parser"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamAuditOnly = "audit-only"
	ParamUnique    = "unique"
)

type Gadget struct{}

func (g *Gadget) Name() string {
	return "capabilities"
}

func (g *Gadget) Category() string {
	return gadgets.CategoryTrace
}

func (g *Gadget) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *Gadget) Description() string {
	return "Trace security capability checks"
}

func (g *Gadget) Params() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamAuditOnly,
			Title:        "Audit Only",
			DefaultValue: "true",
			Description:  "Only show audit checks",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamUnique,
			Title:        "Unique",
			DefaultValue: "false",
			Description:  "Only show a capability once on the same container",
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *Gadget) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *Gadget) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.RegisterGadget(&Gadget{})
}
