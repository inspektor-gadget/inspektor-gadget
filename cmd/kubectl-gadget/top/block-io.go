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
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

type BlockIOParser struct {
	commonutils.BaseParser[types.Stats]

	flags *CommonTopFlags
}

func newBlockIOCmd() *cobra.Command {
	commonTopFlags := &CommonTopFlags{
		CommonFlags: utils.CommonFlags{
			OutputConfig: commonutils.OutputConfig{
				// The columns that will be used in case the user does not specify
				// which specific columns they want to print.
				CustomColumns: []string{
					"node",
					"namespace",
					"pod",
					"container",
					"pid",
					"comm",
					"r/w",
					"major",
					"minor",
					"bytes",
					"time",
					"ios",
				},
			},
		},
	}

	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"comm":      -16,
		"r/w":       -3,
		"major":     -6,
		"minor":     -6,
		"bytes":     -7,
		"time":      -8,
		"ios":       -8,
	}

	cols := types.GetColumns()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("block-io [interval=%d]", top.IntervalDefault),
		Short: "Periodically report block device I/O activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := &BlockIOParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonTopFlags.OutputConfig),
				flags:      commonTopFlags,
			}

			gadget := &TopGadget[types.Stats]{
				name:           "biotop",
				commonTopFlags: commonTopFlags,
				parser:         parser,
				nodeStats:      make(map[string][]*types.Stats),
				colMap:         cols.GetColumnMap(),
			}

			return gadget.Run(args)
		},
		Args: cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, commonTopFlags, &commonTopFlags.CommonFlags, cols.GetColumnNames(), types.SortByDefault)

	return cmd
}

func (p *BlockIOParser) TransformIntoColumns(stats *types.Stats) string {
	return p.Transform(stats, func(stats *types.Stats) string {
		var sb strings.Builder

		for _, col := range p.OutputConfig.CustomColumns {
			switch col {
			case "node":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Node))
			case "namespace":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Namespace))
			case "pod":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Pod))
			case "container":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Container))
			case "pid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Pid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Comm))
			case "r/w":
				rw := 'R'
				if stats.Write {
					rw = 'W'
				}

				sb.WriteString(fmt.Sprintf("%*c", p.ColumnsWidth[col], rw))
			case "major":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Major))
			case "minor":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Minor))
			case "bytes":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Bytes))
			case "time":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.MicroSecs))
			case "ios":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Operations))
			}
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
