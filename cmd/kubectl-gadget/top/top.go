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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
)

type CommonTopFlags struct {
	utils.CommonFlags

	OutputInterval int
	MaxRows        int
	SortBy         string
	ParsedSortBy   []string
}

func NewTopCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "top",
		Short: "Gather, sort and periodically report events according to a given criteria",
	}

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newEbpfCmd())
	cmd.AddCommand(newFileCmd())
	cmd.AddCommand(newTCPCmd())

	return cmd
}

func addCommonTopFlags[Stats any](
	command *cobra.Command,
	commonTopFlags *CommonTopFlags,
	commonFlags *utils.CommonFlags,
	colMap columns.ColumnMap[Stats],
	sortBySliceDefault []string,
) {
	command.Flags().IntVarP(&commonTopFlags.MaxRows, "max-rows", "r", top.MaxRowsDefault, "Maximum rows to print")
	validCols, _ := sort.FilterSortableColumns(colMap, colMap.GetColumnNames())
	command.Flags().StringVarP(
		&commonTopFlags.SortBy, "sort",
		"",
		strings.Join(sortBySliceDefault, ","),
		fmt.Sprintf("Sort columns. Join multiple columns with ','. Prefix with '-' to sort descending for that column. Available columns: (%s)", strings.Join(validCols, ", ")))
	utils.AddCommonFlags(command, commonFlags)
}

// TopParser defines the interface that every top-gadget parser has to
// implement.
type TopParser[Stats any] interface {
	// BuildColumnsHeader returns a header to be used when the user requests to
	// present the output in columns.
	BuildColumnsHeader() string
	TransformIntoColumns(*Stats) string
}

// TopGadget represents a gadget belonging to the top category.
type TopGadget[Stats any] struct {
	sync.Mutex

	name           string
	commonTopFlags *CommonTopFlags
	params         map[string]string
	parser         TopParser[Stats]
	nodeStats      map[string][]*Stats
	colMap         columns.ColumnMap[Stats]
}

func (g *TopGadget[Stats]) Run(args []string) error {
	var err error

	if len(args) == 1 {
		g.commonTopFlags.OutputInterval, err = strconv.Atoi(args[0])
		if err != nil {
			return commonutils.WrapInErrInvalidArg("<interval>",
				fmt.Errorf("%q is not a valid value", args[0]))
		}
	} else {
		g.commonTopFlags.OutputInterval = top.IntervalDefault
	}

	sortByColumns := strings.Split(g.commonTopFlags.SortBy, ",")
	_, invalidCols := sort.FilterSortableColumns(g.colMap, sortByColumns)

	if len(invalidCols) > 0 {
		return commonutils.WrapInErrInvalidArg("--sort", fmt.Errorf("invalid columns to sort by: %q", strings.Join(invalidCols, ",")))
	}
	g.commonTopFlags.ParsedSortBy = sortByColumns

	if g.params == nil {
		g.params = make(map[string]string)
	}
	g.params[top.MaxRowsParam] = strconv.Itoa(g.commonTopFlags.MaxRows)
	g.params[top.IntervalParam] = strconv.Itoa(g.commonTopFlags.OutputInterval)
	g.params[top.SortByParam] = g.commonTopFlags.SortBy

	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      &g.commonTopFlags.CommonFlags,
		Parameters:       g.params,
	}

	// when params.Timeout == interval it means the user
	// only wants to run for a given amount of time and print
	// that result.
	singleShot := g.commonTopFlags.Timeout == g.commonTopFlags.OutputInterval

	// start print loop if this is not a "single shot" operation
	if singleShot {
		g.PrintHeader()
	} else {
		g.StartPrintLoop()
	}

	if err := utils.RunTraceStreamCallback(config, g.Callback); err != nil {
		return commonutils.WrapInErrRunGadget(err)
	}

	if singleShot {
		g.PrintStats()
	}

	return nil
}

func (g *TopGadget[Stats]) StartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(g.commonTopFlags.OutputInterval) * time.Second)
		g.PrintHeader()
		for {
			<-ticker.C
			g.PrintHeader()
			g.PrintStats()
		}
	}()
}

func (g *TopGadget[Stats]) PrintHeader() {
	if g.commonTopFlags.OutputMode == commonutils.OutputModeJSON {
		return
	}

	if term.IsTerminal(int(os.Stdout.Fd())) {
		utils.ClearScreen()
	} else {
		fmt.Println("")
	}

	fmt.Println(g.parser.BuildColumnsHeader())
}

func (g *TopGadget[Stats]) Callback(line string, node string) {
	var event top.Event[Stats]

	if err := json.Unmarshal([]byte(line), &event); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s", commonutils.WrapInErrUnmarshalOutput(err, line))
		return
	}

	if event.Error != "" {
		fmt.Fprintf(os.Stderr, "Error: failed on node %q: %s", node, event.Error)
		return
	}

	g.Lock()
	defer g.Unlock()
	g.nodeStats[node] = event.Stats
}

func (g *TopGadget[Stats]) PrintStats() {
	// Sort and print stats
	g.Lock()

	stats := []*Stats{}
	for _, stat := range g.nodeStats {
		stats = append(stats, stat...)
	}
	g.nodeStats = make(map[string][]*Stats)

	g.Unlock()

	top.SortStats(stats, g.commonTopFlags.ParsedSortBy, &g.colMap)

	for idx, stat := range stats {
		if idx == g.commonTopFlags.MaxRows {
			break
		}
		fmt.Println(g.parser.TransformIntoColumns(stat))
	}
}
