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

	"github.com/spf13/cobra"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	socketcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type SnapshotEvent interface {
	socketcollectortypes.Event | processcollectortypes.Event

	// TODO: The Go compiler does not support accessing a struct field x.f where
	// x is of type parameter type even if all types in the type parameter's
	// type set have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() *eventtypes.Event
}

// SnapshotParser defines the interface that every snapshot-gadget parser has to
// implement.
type SnapshotParser[Event any] interface {
	// SortEvents sorts a slice of events based on a predefined prioritization.
	SortEvents(*[]Event)

	// TransformToColumns is called to transform an event to columns.
	TransformToColumns(*Event) string

	// BuildColumnsHeader returns a header with the requested custom columns
	// that exist in the predefined columns list. The columns are separated by
	// tabs.
	BuildColumnsHeader() string

	// GetOutputConfig returns the output configuration.
	GetOutputConfig() *commonutils.OutputConfig
}

// SnapshotGadgetPrinter is in charge of printing the event of a snapshot gadget
// using the parser.
type SnapshotGadgetPrinter[Event SnapshotEvent] struct {
	Parser SnapshotParser[Event]
}

func (g *SnapshotGadgetPrinter[Event]) PrintEvents(allEvents []Event) error {
	g.Parser.SortEvents(&allEvents)

	outputConfig := g.Parser.GetOutputConfig()
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
		fmt.Println(g.Parser.BuildColumnsHeader())

		for _, e := range allEvents {
			baseEvent := e.GetBaseEvent()
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.HandleSpecialEvent(baseEvent, outputConfig.Verbose)
				continue
			}

			fmt.Println(g.Parser.TransformToColumns(&e))
		}
	}

	return nil
}

func NewCommonSnapshotCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "snapshot",
		Short: "Take a snapshot of a subsystem and print it",
	}
}
