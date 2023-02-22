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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/cpu/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamUserStack   = "user-stack"
	ParamKernelStack = "kernel-stack"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "cpu"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryProfile
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeProfile
}

func (g *GadgetDesc) Description() string {
	return "Analyze CPU performance by sampling stack traces"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
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

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Report](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Report{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
