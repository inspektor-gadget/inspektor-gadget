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
	"fmt"
	"os"
	"os/signal"
	"syscall"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/containerd"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/docker"
)

func main() {
	// Function that will be called for events. event contains
	// information about the kind of event (added, removed) and an
	// instance of the container.
	callback := func(event containercollection.PubSubEvent) {
		switch event.Type {
		case containercollection.EventTypeAddContainer:
			fmt.Printf("Container added: %q pid %d\n",
				event.Container.Name, event.Container.Pid)
		case containercollection.EventTypeRemoveContainer:
			fmt.Printf("Container removed: %q pid %d\n",
				event.Container.Name, event.Container.Pid)
		}
	}

	// Define the different options for the container collection instance
	opts := []containercollection.ContainerCollectionOption{
		// Indicate the callback that will be invoked each time
		// there is an event
		containercollection.WithPubSub(callback),

		// Get containers created with runc
		containercollection.WithRuncFanotify(),

		// Enrich those containers with data from the container
		// runtime. docker and containerd in this case.
		// (It's needed to have the name of the container in this example).
		containercollection.WithMultipleContainerRuntimesEnrichment(
			[]*containerutils.RuntimeConfig{
				{Name: docker.Name},
				{Name: containerd.Name},
			}),
	}

	// Create and initialize the container collection
	containerCollection := &containercollection.ContainerCollection{}
	err := containerCollection.Initialize(opts...)
	if err != nil {
		fmt.Printf("failed to initialize container collection: %s\n", err)
		return
	}
	defer containerCollection.Close()

	// Graceful shutdown
	exit := make(chan os.Signal, 1)
	signal.Notify(exit, syscall.SIGINT, syscall.SIGTERM)
	<-exit
}
