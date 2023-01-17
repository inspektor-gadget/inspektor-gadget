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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	ParamUserStack   = "user-stack"
	ParamKernelStack = "kernel-stack"
)

type Gadget struct{}

func (g *Gadget) Name() string {
	return "cpu"
}

func (g *Gadget) Category() string {
	return gadgets.CategoryProfile
}

func (g *Gadget) Type() gadgets.GadgetType {
	return gadgets.TypeProfile
}

func (g *Gadget) Description() string {
	return "Analyze CPU performance by sampling stack traces"
}

func (g *Gadget) Params() params.ParamDescs {
	// TODO: this params could be combined into a single one
	return params.ParamDescs{
		{
			Key:          ParamUserStack,
			Alias:        "U",
			Title:        "User Stack",
			DefaultValue: "false",
			Description:  "Show stacks from user space only (no kernel space stacks)",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamKernelStack,
			Alias:        "K",
			Title:        "Kernel Stack",
			DefaultValue: "false",
			Description:  "Show stacks from kernel space only (no user space stacks)",
			TypeHint:     params.TypeBool,
		},
	}
}

func (g *Gadget) Parser() parser.Parser {
	return parser.NewParser[types.Report](types.GetColumns())
}

func (g *Gadget) EventPrototype() any {
	return &types.Report{}
}

func init() {
	gadgetregistry.RegisterGadget(&Gadget{})
}
