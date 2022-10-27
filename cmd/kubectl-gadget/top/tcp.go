// Copyright 2019-2021 The Inspektor Gadget authors
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
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
)

type TCPFlags struct {
	CommonTopFlags

	ParsedSortBy []string
	FilteredPid  uint
	Family       uint
}

type TCPParser struct {
	commonutils.BaseParser[types.Stats]
	sync.Mutex

	flags     *TCPFlags
	nodeStats map[string][]*types.Stats
	colMap    columns.ColumnMap[types.Stats]
}

func newTCPCmd() *cobra.Command {
	var flags TCPFlags

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
				"ip",
				"saddr",
				"daddr",
				"sent",
				"received",
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
		"ip":        -3,
		"saddr":     -51,
		"daddr":     -51,
		"sent":      -7,
		"received":  -7,
	}

	cols := columns.MustCreateColumns[types.Stats]()

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("tcp [interval=%d]", types.IntervalDefault),
		Short: "Periodically report TCP activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			parser := &TCPParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonFlags.OutputConfig),
				flags:      &flags,
				nodeStats:  make(map[string][]*types.Stats),
			}

			parser.colMap = cols.GetColumnMap()

			if len(args) == 1 {
				flags.OutputInterval, err = strconv.Atoi(args[0])
				if err != nil {
					return commonutils.WrapInErrInvalidArg("<interval>",
						fmt.Errorf("%q is not a valid value", args[0]))
				}
			} else {
				flags.OutputInterval = types.IntervalDefault
			}

			parameters := map[string]string{
				types.MaxRowsParam:  strconv.Itoa(flags.MaxRows),
				types.IntervalParam: strconv.Itoa(flags.OutputInterval),
				types.SortByParam:   flags.SortBy,
			}

			if flags.Family != 0 {
				parameters[types.FamilyParam] = strconv.FormatUint(uint64(flags.Family), 10)
			}

			if flags.FilteredPid != 0 {
				parameters[types.PidParam] = strconv.FormatUint(uint64(flags.FilteredPid), 10)
			}

			config := &utils.TraceConfig{
				GadgetName:       "tcptop",
				Operation:        gadgetv1alpha1.OperationStart,
				TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
				TraceOutputState: gadgetv1alpha1.TraceStateStarted,
				CommonFlags:      commonFlags,
				Parameters:       parameters,
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

	cmd.PersistentFlags().UintVarP(
		&flags.FilteredPid,
		"pid",
		"",
		0,
		"Show only TCP events generated by this particular PID",
	)
	cmd.PersistentFlags().UintVarP(
		&flags.Family,
		"family",
		"f",
		0,
		"Show only TCP events for this IP version: either 4 or 6 (by default all will be printed)",
	)

	return cmd
}

func (p *TCPParser) Callback(line string, node string) {
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

func (p *TCPParser) StartPrintLoop() {
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

func (p *TCPParser) PrintHeader() {
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

func (p *TCPParser) PrintStats() {
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

func (p *TCPParser) TransformStats(stats *types.Stats) string {
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
			case "ip":
				tcpFamily := 4
				if stats.Family == syscall.AF_INET6 {
					tcpFamily = 6
				}

				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], tcpFamily))
			case "saddr":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], fmt.Sprintf("%s:%d", stats.Saddr, stats.Sport)))
			case "daddr":
				sb.WriteString(fmt.Sprintf("%*s", p.ColumnsWidth[col], fmt.Sprintf("%s:%d", stats.Daddr, stats.Dport)))
			case "sent":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Sent/1024))
			case "received":
				sb.WriteString(fmt.Sprintf("%*d", p.ColumnsWidth[col], stats.Received/1024))
			}
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
