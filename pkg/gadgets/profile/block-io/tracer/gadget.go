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
	"encoding/json"
	"fmt"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

type GadgetDesc struct{}

func (g *GadgetDesc) Name() string {
	return "block-io"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryProfile
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeProfile
}

func (g *GadgetDesc) Description() string {
	return "Analyze block I/O performance through a latency distribution"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return nil
}

func (g *GadgetDesc) Parser() parser.Parser {
	return nil
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Report{}
}

func (g *GadgetDesc) OutputFormats() (gadgets.OutputFormats, string) {
	return gadgets.OutputFormats{
		"report": gadgets.OutputFormat{
			Name:        "Report",
			Description: "A histogram showing the I/O time distribution",
			Transform: func(data any) ([]byte, error) {
				var report types.Report
				b, ok := data.([]byte)
				if !ok {
					return nil, fmt.Errorf("type must be []byte and is: %T", data)
				}
				err := json.Unmarshal(b, &report)
				if err != nil {
					return nil, err
				}
				return []byte(report.String()), nil
			},
		},
	}, "report"
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
