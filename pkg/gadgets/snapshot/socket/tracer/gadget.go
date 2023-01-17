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
	"fmt"
	"strings"

	columnhelpers "github.com/inspektor-gadget/inspektor-gadget/internal/column-helpers"
	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamProto  = "proto"
	ParamExtend = "extend"
)

type Gadget struct{}

func (g *Gadget) Name() string {
	return "socket"
}

func (g *Gadget) Category() string {
	return gadgets.CategorySnapshot
}

func (g *Gadget) Type() gadgets.GadgetType {
	return gadgets.TypeOneShot
}

func (g *Gadget) Description() string {
	return "Gather information about TCP and UDP sockets"
}

func (g *Gadget) Params() params.Params {
	var protocols []string
	for protocol := range types.ProtocolsMap {
		protocols = append(protocols, protocol)
	}
	return params.Params{
		{
			Key:            ParamProto,
			Title:          "Protocol",
			DefaultValue:   "all",
			Description:    fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
			IsMandatory:    true,
			PossibleValues: protocols,
		},
	}
}

func (g *Gadget) Columns() columnhelpers.Columns {
	return columnhelpers.NewColumnHelpers[types.Event](types.GetColumns())
}

func (g *Gadget) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.RegisterGadget(&Gadget{})
}
