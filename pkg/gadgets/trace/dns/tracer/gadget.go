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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
)

type gadget struct {
	*gadgets.GadgetWithParams
}

func (g *gadget) Name() string {
	return "dns"
}

func (g *gadget) Category() string {
	return gadgets.CategoryTrace
}

func (g *gadget) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *gadget) Description() string {
	return "The dns gadget traces DNS requests."
}

func (g *gadget) Parser() parser.Parser {
	return parser.NewParser(types.GetColumns())
}

func (g *gadget) EventPrototype() any {
	return &types.Event{}
}

func NewGadget() *gadget {
	return &gadget{
		GadgetWithParams: gadgets.NewGadgetWithParams(nil),
	}
}

func init() {
	gadgetregistry.RegisterGadget(NewGadget())
}
