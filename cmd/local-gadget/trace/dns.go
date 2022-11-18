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

	"github.com/spf13/cobra"

	commontrace "github.com/inspektor-gadget/inspektor-gadget/cmd/common/trace"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection/networktracer"
	dnsTracer "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/tracer"
	dnsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

func newDNSCmd() *cobra.Command {
	var commonFlags utils.CommonFlags

	// The DNS gadget works in a different way than most gadgets: It
	// attaches a new eBPF program to each container when it's
	// created instead of using an eBPF map with the mount
	// namespaces IDs to filter the events. For this reason we can't
	// use the TraceGadget implementation here.
	runCmd := func(*cobra.Command, []string) error {
		localGadgetManager, err := localgadgetmanager.NewManager(commonFlags.RuntimeConfigs)
		if err != nil {
			return commonutils.WrapInErrManagerInit(err)
		}
		defer localGadgetManager.Close()

		// local-gadget is designed to trace containers, hence enable this column
		cols := dnsTypes.GetColumns()
		col, _ := cols.GetColumn("container")
		col.Visible = true

		parser, err := commonutils.NewGadgetParserWithRuntimeInfo(&commonFlags.OutputConfig, cols)
		if err != nil {
			return commonutils.WrapInErrParserCreate(err)
		}

		eventCallback := func(container *containercollection.Container, event dnsTypes.Event) {
			baseEvent := event.GetBaseEvent()
			if baseEvent.Type != eventtypes.NORMAL {
				commonutils.HandleSpecialEvent(baseEvent, commonFlags.Verbose)
				return
			}

			// Enrich with data from container
			if !container.HostNetwork {
				event.Namespace = container.Namespace
				event.Pod = container.Podname
				event.Container = container.Name
			}

			switch commonFlags.OutputMode {
			case commonutils.OutputModeJSON:
				b, err := json.Marshal(event)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: %s", fmt.Sprint(commonutils.WrapInErrMarshalOutput(err)))
					return
				}

				fmt.Println(string(b))
			case commonutils.OutputModeColumns:
				fallthrough
			case commonutils.OutputModeCustomColumns:
				fmt.Println(parser.TransformIntoColumns(&event))
			}
		}

		tracer, err := dnsTracer.NewTracer()
		if err != nil {
			return commonutils.WrapInErrGadgetTracerCreateAndRun(err)
		}
		defer tracer.Close()

		if commonFlags.OutputMode != commonutils.OutputModeJSON {
			fmt.Println(parser.BuildColumnsHeader())
		}

		selector := containercollection.ContainerSelector{
			Name: commonFlags.Containername,
		}

		config := &networktracer.ConnectToContainerCollectionConfig[dnsTypes.Event]{
			Tracer:        tracer,
			Resolver:      &localGadgetManager.ContainerCollection,
			Selector:      selector,
			EventCallback: eventCallback,
			Base:          dnsTypes.Base,
		}
		conn, err := networktracer.ConnectToContainerCollection(config)
		if err != nil {
			return fmt.Errorf("connecting tracer to container collection: %w", err)
		}
		defer conn.Close()

		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop

		return nil
	}

	cmd := commontrace.NewDNSCmd(runCmd)

	utils.AddCommonFlags(cmd, &commonFlags)

	return cmd
}
