// Copyright 2019-2022 The Inspektor Gadget authors
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

package top

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/docker/go-units"
	"github.com/spf13/cobra"
)

type EbpfParser struct {
	commonutils.BaseParser[types.Stats]

	flags *CommonTopFlags
}

func newEbpfCmd() *cobra.Command {
	commonTopFlags := &CommonTopFlags{
		commonFlags: utils.CommonFlags{
			OutputConfig: commonutils.OutputConfig{
				// The columns that will be used in case the user does not specify
				// which specific columns they want to print.
				CustomColumns: []string{
					"node",
					"progid",
					"type",
					"name",
					"pid",
					"comm",
					"runtime",
					"runcount",
					"mapmemory",
					"mapcount",
				},
			},
		},
	}

	columnsWidth := map[string]int{
		"node":          -16,
		"progid":        -8,
		"type":          -16,
		"name":          -16,
		"pid":           -7,
		"comm":          -20,
		"runtime":       12,
		"runcount":      10,
		"totalruntime":  12,
		"totalruncount": 13,
		"cumulruntime":  12,
		"cumulruncount": 13,
		"mapmemory":     14,
		"mapcount":      8,
	}

	cols := columns.MustCreateColumns[types.Stats]()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("ebpf [interval=%d]", top.IntervalDefault),
		Short: "Periodically report ebpf runtime stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := &EbpfParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonTopFlags.commonFlags.OutputConfig),
				flags:      commonTopFlags,
			}

			gadget := &TopGadget[types.Stats]{
				name:           "ebpftop",
				commonTopFlags: commonTopFlags,
				parser:         parser,
				nodeStats:      make(map[string][]*types.Stats),
				colMap:         cols.GetColumnMap(),
			}

			return gadget.Run(args)
		},
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, commonTopFlags, &commonTopFlags.commonFlags, cols.GetColumnNames(), types.SortByDefault)

	return cmd
}

func (p *EbpfParser) UnmarshalStats(line, node string) ([]*types.Stats, error) {
	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		return nil, commonutils.WrapInErrUnmarshalOutput(err, line)
	}

	if event.Error != "" {
		return nil, fmt.Errorf("error: failed on node %q: %s", node, event.Error)
	}

	return event.Stats, nil
}

func (p *EbpfParser) CollectStats(nodeStats map[string][]*types.Stats) []*types.Stats {
	stats := []*types.Stats{}
	for node, stat := range nodeStats {
		for i := range stat {
			stat[i].Node = node
		}
		stats = append(stats, stat...)
	}
	return stats
}

func (p *EbpfParser) TransformStats(stats *types.Stats) string {
	return p.Transform(stats, func(stats *types.Stats) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Node))
			case "progid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.ProgramID))
			case "type":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Type))
			case "name":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Name))
			case "pid":
				pid := ""
				if len(stats.Pids) > 0 {
					pid = fmt.Sprintf("%d", stats.Pids[0].Pid)
				}
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], pid))
			case "comm":
				comm := ""
				if len(stats.Pids) > 0 {
					comm = stats.Pids[0].Comm
				}
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], comm))
			case "runtime":
				sb.WriteString(fmt.Sprintf("%*v", p.ColumnsWidth[col], time.Duration(stats.CurrentRuntime)))
			case "runcount":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.CurrentRunCount))
			case "totalruntime":
				sb.WriteString(fmt.Sprintf("%*v", p.ColumnsWidth[col], time.Duration(stats.TotalRuntime)))
			case "totalruncount":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.TotalRunCount))
			case "cumulruntime":
				sb.WriteString(fmt.Sprintf("%*v", p.ColumnsWidth[col], time.Duration(stats.CumulativeRuntime)))
			case "cumulruncount":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.CumulativeRunCount))
			case "mapmemory":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], units.BytesSize(float64(stats.MapMemory))))
			case "mapcount":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.MapCount))
			}
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
