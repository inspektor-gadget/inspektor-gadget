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

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/rlimit"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns/formatter/textcolumns"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/tracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

const traceName = "trace_exec"

func main() {
	var containerName string
	flag.StringVar(&containerName, "containername", "", "Show only data from containers with that name")
	flag.Parse()

	if containerName == "" {
		fmt.Printf("you must provide --containername\n")
		return
	}

	// In some kernel versions it's needed to bump the rlimits to
	// use run BPF programs.
	if err := rlimit.RemoveMemlock(); err != nil {
		return
	}

	// Create and initialize the container collection
	containerCollection := &containercollection.ContainerCollection{}

	tracerCollection, err := tracercollection.NewTracerCollection(containerCollection)
	if err != nil {
		fmt.Printf("failed to create trace-collection: %s\n", err)
		return
	}
	defer tracerCollection.Close()

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		// Indicate the callback that will be invoked each time
		// there is an event
		containercollection.WithTracerCollection(tracerCollection),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Enrich events with Linux namespaces information
		// It's needed to be able to filter by containers in this example.
		containercollection.WithLinuxNamespaceEnrichment(),

		// Enrich those containers with data from the container
		// runtime. docker and containerd in this case.
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: runtimeclient.DockerName},
				{Name: runtimeclient.ContainerdName},
			}),
	}

	if err := containerCollection.Initialize(opts...); err != nil {
		fmt.Printf("failed to initialize container collection: %s\n", err)
		return
	}
	defer containerCollection.Close()

	// Create a formatter. It's the component that converts events to columns.
	colNames := []string{"container", "pid", "ppid", "comm", "ret", "args"}
	formatter := textcolumns.NewFormatter(
		types.GetColumns().GetColumnMap(),
		textcolumns.WithDefaultColumns(colNames),
	)

	// Define a callback to be called each time there is an event.
	eventCallback := func(event *types.Event) {
		// Convert the event to columns and print to the terminal.
		fmt.Println(formatter.FormatEntry(event))
	}

	fmt.Println(formatter.FormatHeader())

	// Create a tracer instance. This is the glue piece that allows
	// this example to filter events by containers.
	containerSelector := containercollection.ContainerSelector{
		Name: containerName,
	}

	if err := tracerCollection.AddTracer(traceName, containerSelector); err != nil {
		fmt.Printf("error adding tracer: %s\n", err)
		return
	}
	defer tracerCollection.RemoveTracer(traceName)

	// Get mount namespace map to filter by containers
	mountnsmap, err := tracerCollection.TracerMountNsMap(traceName)
	if err != nil {
		fmt.Printf("failed to get mountnsmap: %s\n", err)
		return
	}

	// Create the tracer
	tracer, err := tracer.NewTracer(&tracer.Config{MountnsMap: mountnsmap}, containerCollection, eventCallback)
	if err != nil {
		fmt.Printf("error creating tracer: %s\n", err)
		return
	}
	defer tracer.Stop()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
