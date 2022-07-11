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

package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/socket-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

// BaseSnapshotParser is a base for a SnapshotParser to reuse the shared
// fields and methods.
type BaseSnapshotParser struct {
	availableCols map[string]struct{}
}

func (p *BaseSnapshotParser) BuildSnapshotColsHeader(requestedCols []string) string {
	var sb strings.Builder

	for _, col := range requestedCols {
		if _, ok := p.availableCols[col]; ok {
			sb.WriteString(strings.ToUpper(col) + "\t")
		}
	}

	return sb.String()
}

type SnapshotEvent interface {
	socketcollectortypes.Event | processcollectortypes.Event

	// The Go compiler does not support accessing a struct field x.f where x is
	// of type parameter type even if all types in the type parameter's type set
	// have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() eventtypes.Event
}

// SnapshotParser defines the interface that every snapshot-gadget parser has to
// implement.
type SnapshotParser[Event SnapshotEvent] interface {
	// SortEvents sorts a slice of events based on a predefined prioritization.
	SortEvents(*[]Event)

	// GetColumnsHeader returns a header based on the requested output format.
	GetColumnsHeader() string

	// TransformEvent is called to transform an event to columns
	// format according to the parameters.
	TransformEvent(*Event) string

	// BuildSnapshotColsHeader returns a header with the requested custom
	// columns that exist in the availableCols. The columns are separated by
	// taps.
	BuildSnapshotColsHeader([]string) string
}

// SnapshotGadget represents a gadget belonging to the snapshot category.
type SnapshotGadget[Event SnapshotEvent] struct {
	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
	parser      SnapshotParser[Event]
}

// Run runs a SnapshotGadget and prints the output after parsing it using the
// SnapshotParser's methods.
func (g *SnapshotGadget[Event]) Run() error {
	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        "collect",
		TraceOutputMode:  "Status",
		TraceOutputState: "Completed",
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// This callback function be called when a snapshot gadget finishes without
	// errors and generates a list of results per node. It merges, sorts and
	// print all of them in the requested mode.
	callback := func(traceOutputMode string, results []string) error {
		allEvents := []Event{}

		for _, r := range results {
			if len(r) == 0 {
				continue
			}

			var events []Event
			if err := json.Unmarshal([]byte(r), &events); err != nil {
				return utils.WrapInErrUnmarshalOutput(err, r)
			}
			allEvents = append(allEvents, events...)
		}

		g.parser.SortEvents(&allEvents)

		switch g.commonFlags.OutputMode {
		case utils.OutputModeJSON:
			b, err := json.MarshalIndent(allEvents, "", "  ")
			if err != nil {
				return utils.WrapInErrMarshalOutput(err)
			}

			fmt.Printf("%s\n", b)
			return nil
		case utils.OutputModeColumns:
			fallthrough
		case utils.OutputModeCustomColumns:
			// In the snapshot gadgets it's possible to use a tabwriter because
			// we have the full list of events to print available, hence the
			// tablewriter is able to determine the columns width. In other
			// gadgets we don't know the size of all columns "a priori", hence
			// we have to do a best effort printing fixed-width columns.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

			fmt.Fprintln(w, g.parser.GetColumnsHeader())

			for _, e := range allEvents {
				baseEvent := e.GetBaseEvent()
				if baseEvent.Type != eventtypes.NORMAL {
					utils.ManageSpecialEvent(baseEvent, g.commonFlags.Verbose)
					continue
				}

				fmt.Fprintln(w, g.parser.TransformEvent(&e))
			}

			w.Flush()
		default:
			return utils.WrapInErrOutputModeNotSupported(g.commonFlags.OutputMode)
		}

		return nil
	}

	return utils.RunTraceAndPrintStatusOutput(config, callback)
}

func NewSnapshotCmd() *cobra.Command {
	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Take a snapshot of a subsystem and print it",
	}

	snapshotCmd.AddCommand(newProcessCmd())
	snapshotCmd.AddCommand(newSocketCmd())

	return snapshotCmd
}
