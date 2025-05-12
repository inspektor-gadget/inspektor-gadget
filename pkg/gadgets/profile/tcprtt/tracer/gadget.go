// Copyright 2023 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"
	"strings"

	gadgetregistry "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-registry"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/tcprtt/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/parser"
)

const (
	ParamMilliseconds          = "milliseconds"
	ParamByLocalAddress        = "byladdr"
	ParamByRemoteAddress       = "byraddr"
	ParamFilterLocalPort       = "lport"
	ParamFilterRemotePort      = "rport"
	ParamFilterLocalAddress    = "laddr"
	ParamFilterRemoteAddress   = "raddr"
	ParamFilterLocalAddressV6  = "laddrv6"
	ParamFilterRemoteAddressV6 = "raddrv6"
)

type GadgetDesc struct {
	gadgets.GadgetDeprecated
}

func (g *GadgetDesc) Name() string {
	return "tcprtt"
}

func (g *GadgetDesc) Category() string {
	return gadgets.CategoryProfile
}

func (g *GadgetDesc) Type() gadgets.GadgetType {
	return gadgets.TypeProfile
}

func (g *GadgetDesc) Description() string {
	return "Analyze TCP connections through an Round-Trip Time (RTT) distribution"
}

func (g *GadgetDesc) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamMilliseconds,
			Alias:        "m",
			DefaultValue: "false",
			Description:  "Show histogram in milliseconds instead of microseconds",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamByLocalAddress,
			Alias:        "b",
			DefaultValue: "false",
			Description:  "Show histogram by local address",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamByRemoteAddress,
			Alias:        "B",
			DefaultValue: "false",
			Description:  "Show histogram by remote address",
			TypeHint:     params.TypeBool,
		},
		{
			Key:          ParamFilterLocalPort,
			Alias:        "",
			DefaultValue: "0",
			Description:  "Filter for local port",
			TypeHint:     params.TypeUint16,
		},
		{
			Key:          ParamFilterRemotePort,
			Alias:        "",
			DefaultValue: "0",
			Description:  "Filter for remote port",
			TypeHint:     params.TypeUint16,
		},
		{
			Key:          ParamFilterLocalAddress,
			Alias:        "", // It was "a" in BCC but ParamFilterRemoteAddress had a conflict
			DefaultValue: "",
			Description:  "Filter for local address",
			TypeHint:     params.TypeIP,
		},
		{
			Key:          ParamFilterRemoteAddress,
			Alias:        "", // It was "A" in BCC but it collides with the alias of ParamAllNamespaces
			DefaultValue: "",
			Description:  "Filter for remote address",
			TypeHint:     params.TypeIP,
		},
		{
			Key:          ParamFilterLocalAddressV6,
			Alias:        "",
			DefaultValue: "",
			Description:  "Filter for local address using IPv6",
			TypeHint:     params.TypeIP,
		},
		{
			Key:          ParamFilterRemoteAddressV6,
			Alias:        "",
			DefaultValue: "",
			Description:  "Filter for remote address using IPv6",
			TypeHint:     params.TypeIP,
		},
	}
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
			Description: "A histogram showing the TCP RTT distribution",
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
				var sb strings.Builder
				for _, h := range report.Histograms {
					sb.WriteString(fmt.Sprintf("%s = %s", h.AddressType, h.Address))

					if h.LocalPort > 0 {
						sb.WriteString(fmt.Sprintf(" Local port = %d", h.LocalPort))
					}

					if h.RemotePort > 0 {
						sb.WriteString(fmt.Sprintf(" Remote port = %d", h.RemotePort))
					}

					if h.Average > 0 {
						sb.WriteString(fmt.Sprintf(" [AVG %f]", h.Average))
					}
					sb.WriteString(fmt.Sprintf("\n%s\n", h.String()))
				}
				return []byte(sb.String()), nil
			},
		},
	}, "report"
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}
