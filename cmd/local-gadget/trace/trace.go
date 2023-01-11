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

package trace

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// TraceGadget represents a gadget belonging to the trace category.
type TraceGadget[Event commontrace.TraceEvent] struct {
	commonFlags        *utils.CommonFlags
	parser             commontrace.TraceParser[Event]
	createAndRunTracer func(*ebpf.Map, gadgets.DataEnricherByMntNs, func(*Event)) (trace.Tracer, error)
}

// Run runs a TraceGadget and prints the output after parsing it using the
// TraceParser's methods.
func (g *TraceGadget[Event]) Run() error {
	localGadgetManager, err := localgadgetmanager.NewManager(g.commonFlags.RuntimeConfigs)
	if err != nil {
		return commonutils.WrapInErrManagerInit(err)
	}
	defer localGadgetManager.Close()

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Name: g.commonFlags.Containername,
	}

	// Create mount namespace map to filter by containers
	mountnsmap, err := localGadgetManager.CreateMountNsMap(containerSelector)
	if err != nil {
		return commonutils.WrapInErrManagerCreateMountNsMap(err)
	}
	defer localGadgetManager.RemoveMountNsMap()

	if g.commonFlags.OutputMode != commonutils.OutputModeJSON {
		fmt.Println(g.parser.BuildColumnsHeader())
	}

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *Event) {
		baseEvent := (*event).GetBaseEvent()
		if baseEvent.Type != eventtypes.NORMAL {
			commonutils.HandleSpecialEvent(baseEvent, g.commonFlags.Verbose)
			return
		}

		switch g.commonFlags.OutputMode {
		case commonutils.OutputModeJSON:
			b, err := json.Marshal(event)
			if err != nil {
				fmt.Fprint(os.Stderr, fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
				return
			}

			fmt.Println(string(b))
		case commonutils.OutputModeColumns:
			fallthrough
		case commonutils.OutputModeCustomColumns:
			fmt.Println(g.parser.TransformIntoColumns(event))
		}
	}

	gadgetTracer, err := g.createAndRunTracer(mountnsmap, &localGadgetManager.ContainerCollection, eventCallback)
	if err != nil {
		return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
	}
	defer gadgetTracer.Stop()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	return nil
}

func NewTraceCmd() *cobra.Command {
	traceCmd := commontrace.NewCommonTraceCmd()

	traceCmd.AddCommand(newBindCmd())
	traceCmd.AddCommand(newCapabilitiesCmd())
	traceCmd.AddCommand(newDNSCmd())
	traceCmd.AddCommand(newExecCmd())
	traceCmd.AddCommand(newFsSlowerCmd())
	traceCmd.AddCommand(newNetworkCmd())
	traceCmd.AddCommand(newOOMKillCmd())
	traceCmd.AddCommand(newOpenCmd())
	traceCmd.AddCommand(newMountCmd())
	traceCmd.AddCommand(newTCPCmd())
	traceCmd.AddCommand(newTcpconnectCmd())
	traceCmd.AddCommand(newSignalCmd())
	traceCmd.AddCommand(newSNICmd())

	return traceCmd
}
