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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/top/file/types"
)

type FileFlags struct {
	CommonTopFlags

	ParsedSortBy types.SortBy
	AllFiles     bool
}

type FileParser struct {
	commonutils.BaseParser[types.Stats]
	sync.Mutex

	flags     *FileFlags
	nodeStats map[string][]types.Stats
}

func newFileCmd() *cobra.Command {
	var flags FileFlags

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
				"reads",
				"writes",
				"r_kb",
				"w_kb",
				"t",
				"file",
			},
		},
	}

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

	cmd := &cobra.Command{
		Use:   fmt.Sprintf("file [interval=%d]", types.IntervalDefault),
		Short: "Periodically report read/write activity by file",
		RunE: func(cmd *cobra.Command, args []string) error {
			var err error

			parser := &FileParser{
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
				GadgetName:       "filetop",
				Operation:        "start",
				TraceOutputMode:  "Stream",
				TraceOutputState: "Started",
				CommonFlags:      commonFlags,
				Parameters: map[string]string{
					types.IntervalParam: strconv.Itoa(flags.OutputInterval),
					types.MaxRowsParam:  strconv.Itoa(flags.MaxRows),
					types.SortByParam:   flags.SortBy,
					types.AllFilesParam: strconv.FormatBool(flags.AllFiles),
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

			if err = utils.RunTraceStreamCallback(config, parser.Callback); err != nil {
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

	cmd.Flags().BoolVarP(&flags.AllFiles, "all-files", "a", types.AllFilesDefault, "Include non-regular file types (sockets, FIFOs, etc)")

	return cmd
}

func (p *FileParser) Callback(line string, node string) {
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

func (p *FileParser) StartPrintLoop() {
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

func (p *FileParser) PrintHeader() {
	switch p.OutputConfig.OutputMode {
	case commonutils.OutputModeColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Printf("%-16s %-16s %-16s %-16s %-7s %-16s %-6s %-6s %-7s %-7s %1s %s\n",
			"NODE", "NAMESPACE", "POD", "CONTAINER",
			"PID", "COMM", "READS", "WRITES", "R_Kb", "W_Kb", "T", "FILE")
	case commonutils.OutputModeCustomColumns:
		if term.IsTerminal(int(os.Stdout.Fd())) {
			utils.ClearScreen()
		} else {
			fmt.Println("")
		}
		fmt.Println(p.GetCustomColsHeader(p.OutputConfig.CustomColumns))
	}
}

func (p *FileParser) PrintEvents() {
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
			fmt.Printf("%-16s %-16s %-16s %-16s %-7d %-16s %-6d %-6d %-7d %-7d %c %s\n",
				event.Node, event.Namespace, event.Pod, event.Container,
				event.Pid, event.Comm, event.Reads, event.Writes, event.ReadBytes/1024,
				event.WriteBytes/1024, event.FileType, event.Filename)
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

func (p *FileParser) GetCustomColsHeader(cols []string) string {
	var sb strings.Builder

	for _, col := range cols {
		switch col {
		case "node":
			sb.WriteString(fmt.Sprintf("%-16s", "NODE"))
		case "namespace":
			sb.WriteString(fmt.Sprintf("%-16s", "NAMESPACE"))
		case "pod":
			sb.WriteString(fmt.Sprintf("%-16s", "POD"))
		case "container":
			sb.WriteString(fmt.Sprintf("%-16s", "CONTAINER"))
		case "pid":
			sb.WriteString(fmt.Sprintf("%-7s", "PID"))
		case "tid":
			sb.WriteString(fmt.Sprintf("%-7s", "TID"))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", "COMM"))
		case "reads":
			sb.WriteString(fmt.Sprintf("%-6s", "READS"))
		case "writes":
			sb.WriteString(fmt.Sprintf("%-6s", "WRITES"))
		case "r_kb":
			sb.WriteString(fmt.Sprintf("%-7s", "R_kb"))
		case "w_kb":
			sb.WriteString(fmt.Sprintf("%-7s", "W_kb"))
		case "t":
			sb.WriteString(fmt.Sprintf("%s", "T"))
		case "file":
			sb.WriteString(fmt.Sprintf("%s", "FILE"))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}

func (p *FileParser) FormatEventCustomCols(stats *types.Stats, cols []string) string {
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
		case "tid":
			sb.WriteString(fmt.Sprintf("%-7d", stats.Tid))
		case "comm":
			sb.WriteString(fmt.Sprintf("%-16s", stats.Comm))
		case "reads":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Reads))
		case "writes":
			sb.WriteString(fmt.Sprintf("%-6d", stats.Writes))
		case "r_kb":
			sb.WriteString(fmt.Sprintf("%-7d", stats.ReadBytes))
		case "w_kb":
			sb.WriteString(fmt.Sprintf("%-7d", stats.WriteBytes))
		case "t":
			sb.WriteString(fmt.Sprintf("%c", stats.FileType))
		case "file":
			sb.WriteString(fmt.Sprintf("%s", stats.Filename))
		}
		sb.WriteRune(' ')
	}

	return sb.String()
}
