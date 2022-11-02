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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

type BlockIOFlags struct {
	CommonTopFlags

	ParsedSortBy []string
}

type BlockIOParser struct {
	commonutils.BaseParser[types.Stats]
	sync.Mutex

	flags     *BlockIOFlags
	nodeStats map[string][]*types.Stats
	colMap    columns.ColumnMap[types.Stats]
}

func newBlockIOCmd() *cobra.Command {
	var flags BlockIOFlags

	commonFlags := &utils.CommonFlags{
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

	cols := columns.MustCreateColumns[types.Stats]()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("block-io [interval=%d]", types.IntervalDefault),
		Short: "Periodically report block device I/O activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			parser := &BlockIOParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonFlags.OutputConfig),
				flags:      &flags,
				nodeStats:  make(map[string][]*types.Stats),
			}

			statCols, err := columns.NewColumns[types.Stats]()
			if err != nil {
				return err
			}
			parser.colMap = statCols.GetColumnMap()

			if len(args) == 1 {
				flags.OutputInterval, err = strconv.Atoi(args[0])
				if err != nil {
					return commonutils.WrapInErrInvalidArg("<interval>",
						fmt.Errorf("%q is not a valid value", args[0]))
				}
			} else {
				flags.OutputInterval = types.IntervalDefault
			}

			config := &utils.TraceConfig{
				GadgetName:       "biotop",
				Operation:        gadgetv1alpha1.OperationStart,
				TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
				TraceOutputState: gadgetv1alpha1.TraceStateStarted,
				CommonFlags:      commonFlags,
				Parameters: map[string]string{
					types.IntervalParam: strconv.Itoa(flags.OutputInterval),
					types.MaxRowsParam:  strconv.Itoa(flags.MaxRows),
					types.SortByParam:   flags.SortBy,
				},
			}

			// when params.Timeout == interval it means the user
			// only wants to run for a given amount of time and print
			// that result.
			singleShot := commonFlags.Timeout == flags.OutputInterval

			// start print loop if this is not a "single shot" operation
			if singleShot {
				parser.PrintHeader()
			} else {
				parser.StartPrintLoop()
			}

			if err := utils.RunTraceStreamCallback(config, parser.Callback); err != nil {
				return commonutils.WrapInErrRunGadget(err)
			}

			if singleShot {
				parser.PrintStats()
			}

			return nil
		},
		SilenceUsage: true,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			sortByColumns := strings.Split(flags.SortBy, ",")
			flags.ParsedSortBy = make([]string, len(sortByColumns))

			for i, col := range sortByColumns {
				colToTest := col
				if len(col) > 0 && col[0] == '-' {
					colToTest = colToTest[1:]
				}
				_, ok := cols.GetColumn(colToTest)
				if !ok {
					return commonutils.WrapInErrInvalidArg("--sort", fmt.Errorf("\"%v\" is not a recognized column to sort by", colToTest))
				}
				flags.ParsedSortBy[i] = col
			}
			return nil
		},
		Args: cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &flags.CommonTopFlags, commonFlags, types.MaxRowsDefault, cols.GetColumnNames())

	return cmd
}

func (p *BlockIOParser) Callback(line string, node string) {
	p.Lock()
	defer p.Unlock()

	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", node, event.Error)
		return
	}

	p.nodeStats[node] = event.Stats
}

func (p *BlockIOParser) StartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(p.flags.OutputInterval) * time.Second)
		p.PrintHeader()
		for {
			_ = <-ticker.C
			p.PrintHeader()
			p.PrintStats()
		}
	}()
}

func (p *BlockIOParser) PrintHeader() {
	if p.OutputConfig.OutputMode == commonutils.OutputModeJSON {
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		utils.ClearScreen()
	} else {
		fmt.Println("")
	}

	fmt.Println(p.BuildColumnsHeader())
}

func (p *BlockIOParser) PrintStats() {
	// Sort and print stats
	p.Lock()

	stats := []*types.Stats{}
	for _, stat := range p.nodeStats {
		stats = append(stats, stat...)
	}
	p.nodeStats = make(map[string][]*types.Stats)

	p.Unlock()

	types.SortStats(stats, p.flags.ParsedSortBy, &p.colMap)

	for idx, stat := range stats {
		if idx == p.flags.MaxRows {
			break
		}
		fmt.Println(p.TransformStats(stat))
	}
}

func (p *BlockIOParser) TransformStats(stats *types.Stats) string {
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
