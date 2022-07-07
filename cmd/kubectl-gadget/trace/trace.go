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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/kinvolk/inspektor-gadget/cmd/kubectl-gadget/utils"

	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"github.com/spf13/cobra"
)

// BaseTraceParser is a base for a TraceParser to reuse the shared fields and
// methods.
type BaseTraceParser struct {
	columnsWidth map[string]int
	outputConfig *utils.OutputConfig
}

func (p *BaseTraceParser) PrintColumnsHeader(requestedCols []string) {
	var sb strings.Builder

	for _, col := range requestedCols {
		if width, ok := p.columnsWidth[col]; ok {
			sb.WriteString(fmt.Sprintf("%*s", width, strings.ToUpper(col)))
		}

		// Needed when field is larger than the predefined columnsWidth.
		sb.WriteRune(' ')
	}

	fmt.Println(sb.String())
}

type TraceEvent interface {
	any

	// The Go compiler does not support accessing a struct field x.f where x is
	// of type parameter type even if all types in the type parameter's type set
	// have a field f. We may remove this restriction in Go 1.19. See
	// https://tip.golang.org/doc/go1.18#generics.
	GetBaseEvent() eventtypes.Event
}

// TraceParser defines the interface that every trace-gadget parser has to
// implement.
type TraceParser[Event TraceEvent] interface {
	// TransformEvent is called to transform an event to columns format.
	TransformEvent(event *Event, requestedColumns []string) string

	// PrintColumnsHeader prints the header with the requested custom columns
	// that exist in the columnsWidth struct.
	PrintColumnsHeader([]string)
}

// TraceGadget represents a gadget belonging to the trace category.
type TraceGadget[Event TraceEvent] struct {
	name        string
	commonFlags *utils.CommonFlags
	params      map[string]string
	parser      TraceParser[Event]
}

// Run runs a TraceGadget and prints the output after parsing it using the
// TraceParser's methods.
func (g *TraceGadget[Event]) Run() error {
	config := &utils.TraceConfig{
		GadgetName:       g.name,
		Operation:        "start",
		TraceOutputMode:  "Stream",
		TraceOutputState: "Started",
		CommonFlags:      g.commonFlags,
		Parameters:       g.params,
	}

	// Print header
	switch g.commonFlags.OutputMode {
	case utils.OutputModeJSON:
		// Nothing to print
	case utils.OutputModeColumns:
		fallthrough
	case utils.OutputModeCustomColumns:
		g.parser.PrintColumnsHeader(g.commonFlags.CustomColumns)
	}

	transformEvent := func(line string) string {
		var e Event

		if err := json.Unmarshal([]byte(line), &e); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s", utils.WrapInErrUnmarshalOutput(err, line))
			return ""
		}

		baseEvent := e.GetBaseEvent()
		if baseEvent.Type != eventtypes.NORMAL {
			utils.ManageSpecialEvent(baseEvent, g.commonFlags.Verbose)
			return ""
		}

		return g.parser.TransformEvent(&e, g.commonFlags.CustomColumns)
	}

	if err := utils.RunTraceAndPrintStream(config, transformEvent); err != nil {
		return utils.WrapInErrRunGadget(err)
	}

	return nil
}

func NewTraceCmd() *cobra.Command {
	traceCmd := &cobra.Command{
		Use:   "trace",
		Short: "Trace and print system events",
	}

	traceCmd.AddCommand(newBindCmd())
	traceCmd.AddCommand(newCapabilitiesCmd())
	traceCmd.AddCommand(newDNSCmd())
	traceCmd.AddCommand(newExecCmd())
	traceCmd.AddCommand(newFsSlowerCmd())
	traceCmd.AddCommand(newMountCmd())
	traceCmd.AddCommand(newNetworkCmd())
	traceCmd.AddCommand(newOOMKillCmd())
	traceCmd.AddCommand(newOpenCmd())
	traceCmd.AddCommand(newSignalCmd())
	traceCmd.AddCommand(newSNICmd())
	traceCmd.AddCommand(newTCPCmd())
	traceCmd.AddCommand(newTcpconnectCmd())

	return traceCmd
}
