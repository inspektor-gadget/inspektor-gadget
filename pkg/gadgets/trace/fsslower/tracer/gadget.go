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

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamFilesystem = "filesystem"
	ParamMinLatency = "min"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "fsslower"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTrace
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Trace open, read, write and fsync operations slower than a threshold"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamMinLatency,
			Alias:        "m",
			Title:        "Minimum Latency",
			DefaultValue: fmt.Sprintf("%d", types.MinLatencyDefault),
			Description:  "Min latency to trace, in ms",
			TypeHint:     params.TypeUint64,
		},
		{
			Key:            ParamFilesystem,
			Alias:          "f",
			Title:          "Filesystem",
			DefaultValue:   "ext4",
			Description:    "Filesystem to trace",
			PossibleValues: []string{"btrfs", "ext4", "nfs", "xfs"},
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
