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

// Package tracer is deprecated.
//
// Deprecated: Switch to image-based gadgets instead. Check
// https://github.com/inspektor-gadget/inspektor-gadget/tree/main/examples/gadgets
package tracer

import (
	"fmt"
	"strings"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamProto  = "proto"
	ParamExtend = "extend"
)

type GadgetDesc struct {
	gadgets.GadgetDeprecated
}

func (g *GadgetDesc) Name() string {
	return "socket"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategorySnapshot
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeOneShot
}

func (g *GadgetDesc) Description() string {
	return "Gather information about TCP and UDP sockets"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	var protocols []string
	for protocol := range types.ProtocolsMap {
		protocols = append(protocols, protocol)
	}
	return params.ParamDescs{
		{
			Key:            ParamProto,
			Title:          "Protocol",
			DefaultValue:   "all",
			Description:    fmt.Sprintf("Show only sockets using this protocol (%s)", strings.Join(protocols, ", ")),
			PossibleValues: protocols,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func (g *GadgetDesc) SortByDefault() []string {
	return []string{
		"k8s.node", "k8s.namespace", "k8s.podName", "protocol", "status", "src", "dst", "inode",
	}
}

func (g *GadgetDesc) SkipParams() []params.ValueHint {
	return []params.ValueHint{gadgets.K8SContainerName}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
