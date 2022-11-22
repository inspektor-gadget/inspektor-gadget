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
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
)

type FileParser struct {
	commonutils.BaseParser[types.Stats]

	flags *CommonTopFlags
}

func newFileCmd() *cobra.Command {
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
					"reads",
					"writes",
					"r_kb",
					"w_kb",
					"t",
					"file",
				},
			},
		},
	}

	var allFiles bool

	columnsWidth := map[string]int{
		"node":      -16,
		"namespace": -16,
		"pod":       -30,
		"container": -16,
		"pid":       -7,
		"tid":       -7,
		"comm":      -16,
		"reads":     -6,
		"writes":    -6,
		"r_kb":      -7,
		"w_kb":      -7,
		"t":         -1,
		"file":      -30,
	}

	cols := types.GetColumns()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("file [interval=%d]", top.IntervalDefault),
		Short: "Periodically report read/write activity by file",
		RunE: func(cmd *cobra.Command, args []string) error {
			parser := &FileParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonTopFlags.OutputConfig),
				flags:      commonTopFlags,
			}

			gadget := &TopGadget[types.Stats]{
				name:           "filetop",
				commonTopFlags: commonTopFlags,
				params: map[string]string{
					types.AllFilesParam: strconv.FormatBool(allFiles),
				},
				parser:    parser,
				nodeStats: make(map[string][]*types.Stats),
				colMap:    cols.GetColumnMap(),
			}

			return gadget.Run(args)
		},
		SilenceUsage: true,
		Args:         cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, commonTopFlags, &commonTopFlags.CommonFlags, cols.GetColumnNames(), types.SortByDefault)

	cmd.Flags().BoolVarP(&allFiles, "all-files", "a", types.AllFilesDefault, "Include non-regular file types (sockets, FIFOs, etc)")

	return cmd
}

func (p *FileParser) TransformStats(stats *types.Stats) string {
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
			case "tid":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Tid))
			case "comm":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Comm))
			case "reads":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Reads))
			case "writes":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Writes))
			case "r_kb":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.ReadBytes/1024))
			case "w_kb":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.WriteBytes/1024))
			case "t":
				sb.WriteString(fmt.Sprintf("%*c", p.ColumnsWidth[col], stats.FileType))
			case "file":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], stats.Filename))
			}
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
