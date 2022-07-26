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

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/block-io/types"
)

type BlockIOFlags struct {
	CommonTopFlags

	ParsedSortBy types.SortBy
}

type BlockIOParser struct {
	commonutils.BaseParser[types.Stats]
	sync.Mutex

	flags     *BlockIOFlags
	nodeStats map[string][]types.Stats
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

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("block-io [interval=%d]", types.IntervalDefault),
		Short: "Periodically report block device I/O activity",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			parser := &BlockIOParser{
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
				GadgetName:       "biotop",
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
				parser.PrintEvents()
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

			return nil
		},
		Args: cobra.MaximumNArgs(1),
	}

	addCommonTopFlags(cmd, &flags.CommonTopFlags, commonFlags, types.MaxRowsDefault, types.SortBySlice)

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
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", event.Node, event.Error)
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
			p.PrintEvents()
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

func (p *BlockIOParser) PrintEvents() {
	// sort and print events
	p.Lock()

	stats := []types.Stats{}
	for _, stat := range p.nodeStats {
		stats = append(stats, stat...)
	}
	p.nodeStats = make(map[string][]types.Stats)

	p.Unlock()

	types.SortStats(stats, p.flags.ParsedSortBy)

	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeColumns:
		for idx, event := range stats {
			if idx == p.flags.MaxRows {
				break
			}

			rw := 'R'
			if event.Write {
				rw = 'W'
			}

			fmt.Printf("%-16s %-16s %-16s %-16s %-7d %-16s %-3c %-6d %-6d %-7d %-8d %d\n",
				event.Node, event.Namespace, event.Pod, event.Container,
				event.Pid, event.Comm, rw, event.Major, event.Minor, event.Bytes,
				event.MicroSecs, event.Operations)
		}
	case commonutils.OutputModeJSON:
		b, err := json.Marshal(stats)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrMarshalOutput(err))
			return
		}
		fmt.Println(string(b))
	case commonutils.OutputModeCustomColumns:
		for idx, stat := range stats {
			if idx == p.flags.MaxRows {
				break
			}
			fmt.Println(p.FormatEventCustomCols(&stat, p.OutputConfig.CustomColumns))
		}
	}
}


func (p *BlockIOParser) FormatEventCustomCols(stats *types.Stats, cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Node))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Namespace))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Pod))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Container))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Pid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Comm))
		case "r/w":
			rw := 'R'
			if stats.Write {
				rw = 'W'
			}

			sb.WriteString(fmt.Sprintf("%-3c", rw))
		case "major":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Major))
		case "minor":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Minor))
		case "bytes":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Bytes))
		case "time":
			sb.WriteString(fmt.Sprintf("%-8d", stats.MicroSecs))
		case "ios":
			sb.WriteString(fmt.Sprintf("%-8d", stats.Operations))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
