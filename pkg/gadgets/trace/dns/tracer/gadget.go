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
	"time"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamDNSTimeout = "dns-timeout"
	ParamPorts      = "ports"
	ParamPaths      = "paths"
)

type GadgetDesc struct {
	gadgets.GadgetDeprecated
}

func (g *GadgetDesc) Name() string {
	return "dns"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryTrace
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeTrace
}

func (g *GadgetDesc) Description() string {
	return "Trace DNS requests"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamPaths,
			Title:        "Additional paths",
			Description:  "Show current working directory and executable path",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamDNSTimeout,
			Title:        "dns-timeout",
			DefaultValue: "10s",
			Description:  "Timeout waiting for a response to a DNS query (used to calculate latency)",
			TypeHint:     params.TypeDuration,
			Validator: func(value string) error {
				d, err := time.ParseDuration(value)
				if err != nil {
					return err
				}

				if d <= 0 {
					return fmt.Errorf("DNS timeout must be > 0")
				}

				return nil
			},
		},
		{
			Key:          ParamPorts,
			Alias:        "P",
			DefaultValue: "53,5353",
			Description:  "Ports to trace DNS requests on",
			Validator:    params.ValidateSlice(params.ValidateUintRange(1, 65535)),
		},
	}
}

func (g *GadgetDesc) Parser() parser.Parser {
	return parser.NewParser[types.Event](types.GetColumns())
}

func (g *GadgetDesc) EventPrototype() any {
	return &types.Event{}
}

func (g *GadgetDesc) SkipParams() []params.ValueHint {
	return []params.ValueHint{gadgets.K8SContainerName}
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
