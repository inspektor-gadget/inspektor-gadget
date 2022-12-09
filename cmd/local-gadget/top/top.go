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
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/spf13/cobra"

	commontop "github.com/inspektor-gadget/inspektor-gadget/cmd/common/top"
	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/cmd/local-gadget/utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/sort"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-collection/gadgets/trace"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
)

// TopGadget represents a gadget belonging to the top category.
type TopGadget[Stats any] struct {
	commontop.TopGadget[Stats]

	commonFlags        *utils.CommonFlags
	createAndRunTracer func(*ebpf.Map, gadgets.DataEnricher, func(*top.Event[Stats])) (trace.Tracer, error)
}

// Run runs a TopGadget and prints the output after parsing it using the
// TopParser's methods.
func (g *TopGadget[Stats]) Run(args []string) error {
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

	if len(args) == 1 {
		g.CommonTopFlags.OutputInterval, err = strconv.Atoi(args[0])
		if err != nil {
			return commonutils.WrapInErrInvalidArg("<interval>", fmt.Errorf("%q is not a valid value", args[0]))
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

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *top.Event[Stats]) {
		g.PrintHeader()
		g.PrintStats(event.Stats)
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

func NewTopCmd() *cobra.Command {
	cmd := commontop.NewCommonTopCmd()

	cmd.AddCommand(newBlockIOCmd())

	return cmd
}
