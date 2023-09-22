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

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamThreads = "threads"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "process"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategorySnapshot
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeOneShot
}

func (g *GadgetDesc) Description() string {
	return "Gather information about running processes"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamThreads,
			Title:        "Show all threads",
			Alias:        "", // TODO: was t, clashes with timeout
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func (g *GadgetDesc) OutputFormats() (gadgets.OutputFormats, string) {
	return gadgets.OutputFormats{
		"tree": gadgets.OutputFormat{
			Name:        "Tree",
			Description: "A pstree like output",
			Transform: func(data any) ([]byte, error) {
				processes, ok := data.([]*types.Event)
				if !ok {
					return nil, fmt.Errorf("type must be []*types.Event and is: %T", data)
				}

				var builder strings.Builder
				err := types.WriteTree(&builder, processes)
				if err != nil {
					return nil, err
				}

				return []byte(builder.String()), nil
			},
		},
	}, "columns"
}

func (g *GadgetDesc) SortByDefault() []string {
	return []string{"k8s.node", "k8s.namespace", "k8s.pod", "k8s.container", "comm", "pid", "tid", "ppid"}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
