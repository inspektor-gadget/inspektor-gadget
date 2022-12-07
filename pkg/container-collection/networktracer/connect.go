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

package networktracer

import (
	"fmt"

	"github.com/google/uuid"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type Tracer[Event any] interface {
	Attach(pid uint32, eventCallback func(Event)) error
	Detach(pid uint32) error
}

type ConnectionToContainerCollection struct {
	subKey   string
	resolver containercollection.ContainerResolver
}

func (c *ConnectionToContainerCollection) Close() {
	c.resolver.Unsubscribe(c.subKey)
}

type ConnectToContainerCollectionConfig[Event any] struct {
	Tracer        Tracer[Event]
	Resolver      containercollection.ContainerResolver
	Selector      containercollection.ContainerSelector
	EventCallback func(*containercollection.Container, Event)
	Base          func(eventtypes.Event) Event
}

// ConnectToContainerCollection connects a networking tracer to the
// container collection package. It creates the needed logic to call the
// Attach() function on the tracer each time a container is created and
// to call Detach() each time the container is removed. Callers must
// call Close() on the returned ConnectionToContainerCollection object.
func ConnectToContainerCollection[Event any](
	config *ConnectToContainerCollectionConfig[Event],
) (*ConnectionToContainerCollection, error) {
	// Variables to avoid using c. in all the places below
	id := uuid.New()
	subscribeKey := id.String()
	tracer := config.Tracer
	resolver := config.Resolver
	selector := config.Selector
	eventCallback := config.EventCallback
	base := config.Base

	attachContainerFunc := func(container *containercollection.Container) {
		cbWithContainer := func(ev Event) {
			eventCallback(container, ev)
		}
		err := tracer.Attach(container.Pid, cbWithContainer)
		if err != nil {
			msg := fmt.Sprintf("start tracing container %q: %s", container.Name, err)
			eventCallback(container, base(eventtypes.Err(msg)))
			return
		}
		eventCallback(container, base(eventtypes.Debug("tracer attached")))
	}

	detachContainerFunc := func(container *containercollection.Container) {
		err := tracer.Detach(container.Pid)
		if err != nil {
			msg := fmt.Sprintf("stop tracing container %q: %s", container.Name, err)
			eventCallback(container, base(eventtypes.Err(msg)))
			return
		}
		eventCallback(container, base(eventtypes.Debug("tracer detached")))
	}

	containers := resolver.Subscribe(
		subscribeKey,
		selector,
		func(event containercollection.PubSubEvent) {
			switch event.Type {
			case containercollection.EventTypeAddContainer:
				attachContainerFunc(event.Container)
			case containercollection.EventTypeRemoveContainer:
				detachContainerFunc(event.Container)
			}
		},
	)

	for _, container := range containers {
		attachContainerFunc(container)
	}
	return &ConnectionToContainerCollection{
		subKey:   subscribeKey,
		resolver: resolver,
	}, nil
}
