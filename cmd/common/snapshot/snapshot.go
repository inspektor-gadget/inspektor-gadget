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

package snapshot

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	commonutils "github.com/kinvolk/inspektor-gadget/cmd/common/utils"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	socketcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/spf13/cobra"
)

type SnapshotEvent interface {
	socketcollectortypes.Event | processcollectortypes.Event

	// TODO: The Go compiler does not support accessing a struct field x.f where
	// x is of type parameter type even if all types in the type parameter's
	// type set have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() eventtypes.Event
}

// SnapshotParser defines the interface that every snapshot-gadget parser has to
// implement.
type SnapshotParser[Event SnapshotEvent] interface {
	// SortEvents sorts a slice of events based on a predefined prioritization.
	SortEvents(*[]Event)

	// TransformToColumns is called to transform an event to columns.
	TransformToColumns(*Event) string

	// BuildColumnsHeader returns a header with the requested custom columns
	// that exist in the predefined columns list. The columns are separated by
	// tabs.
	BuildColumnsHeader() string

	// GetOutputConfig returns the output configuration. TODO: This method is
	// required because of the same limitation of SnapshotEvent.GetBaseEvent().
	// The Go compiler does not support accessing SnapshotParser.OutputConfig.
	GetOutputConfig() *commonutils.OutputConfig
}

// SnapshotGadget represents a gadget belonging to the snapshot category.
type SnapshotGadget[Event SnapshotEvent] struct {
	parser    SnapshotParser[Event]
	customRun func(callback func(traceOutputMode string, results []string) error) error
}

// Run runs a SnapshotGadget and prints the output after parsing it using the
// SnapshotParser's methods.
func (g *SnapshotGadget[Event]) Run() error {
	// This function is called when a snapshot gadget finishes without errors and
	// generates a list of results per node. It merges, sorts and print all of them
	// in the requested mode.
	callback := func(traceOutputMode string, results []string) error {
		allEvents := []Event{}

		for _, r := range results {
			if len(r) == 0 {
				continue
			}

			var events []Event
			if err := json.Unmarshal([]byte(r), &events); err != nil {
				return commonutils.WrapInErrUnmarshalOutput(err, r)
			}
			allEvents = append(allEvents, events...)
		}

		g.parser.SortEvents(&allEvents)

		outputConfig := g.parser.GetOutputConfig()
		switch outputConfig.OutputMode {
		case commonutils.OutputModeJSON:
			b, err := json.MarshalIndent(allEvents, "", "  ")
			if err != nil {
				return commonutils.WrapInErrMarshalOutput(err)
			}

			fmt.Printf("%s\n", b)
			return nil
		case commonutils.OutputModeColumns:
			fallthrough
		case commonutils.OutputModeCustomColumns:
			// In the snapshot gadgets it's possible to use a tabwriter because
			// we have the full list of events to print available, hence the
			// tablewriter is able to determine the columns width. In other
			// gadgets we don't know the size of all columns "a priori", hence
			// we have to do a best effort printing fixed-width columns.
			w := tabwriter.NewWriter(os.Stdout, 0, 0, 4, ' ', 0)

			fmt.Fprintln(w, g.parser.BuildColumnsHeader())

			for _, e := range allEvents {
				baseEvent := e.GetBaseEvent()
				if baseEvent.Type != eventtypes.NORMAL {
					commonutils.ManageSpecialEvent(&baseEvent, outputConfig.Verbose)
					continue
				}

				fmt.Fprintln(w, g.parser.TransformToColumns(&e))
			}

			w.Flush()
		default:
			return commonutils.WrapInErrOutputModeNotSupported(outputConfig.OutputMode)
		}

		return nil
	}

	return g.customRun(callback)
}

func NewCommonSnapshotCmd() *cobra.Command {
	snapshotCmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Take a snapshot of a subsystem and print it",
	}

	return snapshotCmd
}
