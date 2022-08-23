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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/ebpf/types"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

type EbpfFlags struct {
	CommonTopFlags

	ParsedSortBy types.SortBy
}

type EbpfParser struct {
	commonutils.BaseParser[types.Stats]
	sync.Mutex

	flags     *EbpfFlags
	nodeStats map[string][]types.Stats
}

func newEbpfCmd() *cobra.Command {
	var flags EbpfFlags

	commonFlags := &utils.CommonFlags{
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
	}

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("ebpf [interval=%d]", types.IntervalDefault),
		Short: "Periodically report ebpf runtime stats",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			parser := &EbpfParser{
				BaseParser: commonutils.NewBaseWidthParser[types.Stats](columnsWidth, &commonFlags.OutputConfig),
				flags:      &flags,
				nodeStats:  make(map[string][]types.Stats),
			}

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
				GadgetName:       "ebpftop",
				Operation:        "start",
				TraceOutputMode:  "Stream",
				TraceOutputState: "Started",
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
			var err error
			flags.ParsedSortBy, err = types.ParseSortBy(flags.SortBy)
			if err != nil {
				return commonutils.WrapInErrInvalidArg("--sort", err)
			}

			if commonFlags.NamespaceOverridden {
				return commonutils.WrapInErrInvalidArg("--namespace / -n",
					fmt.Errorf("this gadget cannot filter by namespace"))
			}
			if commonFlags.Podname != "" {
				return commonutils.WrapInErrInvalidArg("--podname / -p",
					fmt.Errorf("this gadget cannot filter by pod name"))
			}
			if commonFlags.Containername != "" {
				return commonutils.WrapInErrInvalidArg("--containername / -c",
					fmt.Errorf("this gadget cannot filter by container name"))
			}
			if len(commonFlags.Labels) > 0 {
				return commonutils.WrapInErrInvalidArg("--selector / -l",
					fmt.Errorf("this gadget cannot filter by selector"))
			}

			return nil
		},
		Args: cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &flags.CommonTopFlags, commonFlags, types.MaxRowsDefault, types.SortBySlice)

	return cmd
}

func (p *EbpfParser) Callback(line string, node string) {
	p.Lock()
	defer p.Unlock()

	var event types.Event

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", event.Node, event.Error)
		return
	}

	p.nodeStats[node] = event.Stats
}

func (p *EbpfParser) StartPrintLoop() {
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

func (p *EbpfParser) PrintHeader() {
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

func (p *EbpfParser) PrintStats() {
	// Sort and print stats
	p.Lock()

	stats := []types.Stats{}
	for node, stat := range p.nodeStats {
		for i := range stat {
			stat[i].Node = node
		}
		stats = append(stats, stat...)
	}
	p.nodeStats = make(map[string][]types.Stats)

	p.Unlock()

	types.SortStats(stats, p.flags.ParsedSortBy)

	for idx, stat := range stats {
		if idx == p.flags.MaxRows {
			break
		}
		fmt.Println(p.TransformStats(&stat))
	}
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
			}
			sb.WriteRune(' ')
		}

		return sb.String()
	})
}
