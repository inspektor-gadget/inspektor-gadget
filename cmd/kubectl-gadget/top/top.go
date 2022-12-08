// Copyright 2022 The Inspektor Gadget authors
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

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/kubectl-gadget/utils"
	gadgetv1alpha1 "github.com/inspektor-gadget/inspektor-gadget/pkg/apis/gadget/v1alpha1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
)

// TopGadget represents a gadget belonging to the top category.
type TopGadget[Stats any] struct {
	commontop.TopGadget[Stats]
	sync.Mutex

	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
	nodeStats   map[string][]*Stats
}

func (g *TopGadget[Stats]) Run(args []string) error {
	var err error

	if len(args) == 1 {
		g.CommonTopFlags.OutputInterval, err = strconv.Atoi(args[0])
		if err != nil {
			return commonutils.WrapInErrInvalidArg("<interval>",
				fmt.Errorf("%q is not a valid value", args[0]))
		}
	} else {
		g.CommonTopFlags.OutputInterval = top.IntervalDefault
	}

	sortByColumns := strings.Split(g.CommonTopFlags.SortBy, ",")
	_, invalidCols := sort.FilterSortableColumns(g.ColMap, sortByColumns)

	if len(invalidCols) > 0 {
		return commonutils.WrapInErrInvalidArg("--sort", fmt.Errorf("invalid columns to sort by: %q", strings.Join(invalidCols, ",")))
	}
	g.CommonTopFlags.ParsedSortBy = sortByColumns

	if g.params == nil {
		g.params = make(map[string]string)
	}
	g.params[top.MaxRowsParam] = strconv.Itoa(g.CommonTopFlags.MaxRows)
	g.params[top.IntervalParam] = strconv.Itoa(g.CommonTopFlags.OutputInterval)
	g.params[top.SortByParam] = g.CommonTopFlags.SortBy

	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        gadgetv1alpha1.OperationStart,
		TraceOutputMode:  gadgetv1alpha1.TraceOutputModeStream,
		TraceOutputState: gadgetv1alpha1.TraceStateStarted,
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// when params.Timeout == interval it means the user
	// only wants to run for a given amount of time and print
	// that result.
	singleShot := g.commonFlags.Timeout == g.CommonTopFlags.OutputInterval

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
		g.mergeAndPrintStats()
	}

	return nil
}

func (g *TopGadget[Stats]) StartPrintLoop() {
	go func() {
		ticker := time.NewTicker(time.Duration(g.CommonTopFlags.OutputInterval) * time.Second)
		g.PrintHeader()
		for {
			<-ticker.C
			g.PrintHeader()
			g.mergeAndPrintStats()
		}
	}()
}

func (g *TopGadget[Stats]) mergeAndPrintStats() {
	// Sort and print stats
	g.Lock()

	stats := []*Stats{}
	for _, stat := range g.nodeStats {
		stats = append(stats, stat...)
	}
	g.nodeStats = make(map[string][]*Stats)

	g.Unlock()

	g.PrintStats(stats)
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

func NewTopCmd() *cobra.Command {
	cmd := commontop.NewCommonTopCmd()

	cmd.AddCommand(newBlockIOCmd())
	cmd.AddCommand(newEbpfCmd())
	cmd.AddCommand(newFileCmd())
	cmd.AddCommand(newTCPCmd())

	return cmd
}
