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
	"strings"

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
				return []byte(reportToString(report)), nil
			},
		},
	}, "report"
}

func init() {
	gadgetregistry.Register(&GadgetDesc{})
}

// --- moved from cmd/common/profile, should be removed there

// starsToString prints a line of the histogram.
// It is a golang translation of iovisor/bcc print_stars():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L878-L893
func starsToString(val, valMax, width uint64) string {
	if valMax == 0 {
		return strings.Repeat(" ", int(width))
	}

	minVal := uint64(0)
	if val < valMax {
		minVal = val
	} else {
		minVal = valMax
	}

	stars := minVal * width / valMax
	spaces := width - stars

	var sb strings.Builder
	sb.WriteString(strings.Repeat("*", int(stars)))
	sb.WriteString(strings.Repeat(" ", int(spaces)))
	if val > valMax {
		sb.WriteByte('+')
	}

	return sb.String()
}

// reportToString prints a histogram from a types.Report.
// It is a golang adaption of iovisor/bcc print_log2_hist():
// https://github.com/iovisor/bcc/blob/13b5563c11f7722a61a17c6ca0a1a387d2fa7788/libbpf-tools/trace_helpers.c#L895-L932
func reportToString(report types.Report) string {
	if len(report.Data) == 0 {
		return ""
	}

	valMax := uint64(0)
	for _, data := range report.Data {
		if data.Count > valMax {
			valMax = data.Count
		}
	}

	// reportEntries maximum value is C.MAX_SLOTS which is 27, so we take the
	// value when idx_max <= 32.
	spaceBefore := 5
	spaceAfter := 19
	width := 10
	stars := 40

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%*s%-*s : count    distribution\n", spaceBefore,
		"", spaceAfter, report.ValType))

	for _, data := range report.Data {
		sb.WriteString(fmt.Sprintf("%*d -> %-*d : %-8d |%s|\n", width,
			data.IntervalStart, width, data.IntervalEnd, data.Count,
			starsToString(data.Count, valMax, uint64(stars))))
	}

	return sb.String()
}
