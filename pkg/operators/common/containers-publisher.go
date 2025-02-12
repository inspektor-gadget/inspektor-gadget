// Copyright 2025 The Inspektor Gadget authors
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

package common

import (
	"fmt"

	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
)

type ContainersPublisher struct {
	collection *containercollection.ContainerCollection

	containersDs              datasource.DataSource
	eventTypeField            datasource.FieldAccessor
	idField                   datasource.FieldAccessor
	cgroupIDField             datasource.FieldAccessor
	mountNsIDField            datasource.FieldAccessor
	nameField                 datasource.FieldAccessor
	containerConfigField      datasource.FieldAccessor
	pidField                  datasource.FieldAccessor
	containersSubscriptionKey string
}

func NewContainersPublisher(gadgetCtx operators.GadgetContext, collection *containercollection.ContainerCollection) (*ContainersPublisher, error) {
	publisher := &ContainersPublisher{}
	var err error

	publisher.containersDs, err = gadgetCtx.RegisterDataSource(datasource.TypeSingle, "containers")
	if err != nil {
		return nil, fmt.Errorf("creating datasource: %w", err)
	}
	publisher.containersDs.AddAnnotation("cli.default-output-mode", "none")

	publisher.eventTypeField, err = publisher.containersDs.AddField("event_type", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field event_type: %w", err)
	}

	publisher.idField, err = publisher.containersDs.AddField("container_id", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field container_id: %w", err)
	}

	publisher.cgroupIDField, err = publisher.containersDs.AddField("cgroup_id", api.Kind_Uint64)
	if err != nil {
		return nil, fmt.Errorf("adding field cgroup_id: %w", err)
	}

	publisher.mountNsIDField, err = publisher.containersDs.AddField("mntns_id", api.Kind_Uint64)
	if err != nil {
		return nil, fmt.Errorf("adding field mntns_id: %w", err)
	}

	publisher.nameField, err = publisher.containersDs.AddField("name", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field name: %w", err)
	}

	publisher.containerConfigField, err = publisher.containersDs.AddField("container_config", api.Kind_String)
	if err != nil {
		return nil, fmt.Errorf("adding field container_config: %w", err)
	}

	publisher.pidField, err = publisher.containersDs.AddField("pid", api.Kind_Uint32)
	if err != nil {
		return nil, fmt.Errorf("adding field pid: %w", err)
	}

	publisher.collection = collection

	return publisher, nil
}

func (publisher *ContainersPublisher) emitContainersDatasourceEvent(eventType containercollection.EventType, container *containercollection.Container, k8s bool) error {
	ev, err := publisher.containersDs.NewPacketSingle()
	if err != nil {
		return fmt.Errorf("creating new containers datasource packet: %w", err)
	}

	publisher.eventTypeField.PutString(ev, eventType.String())
	publisher.idField.PutString(ev, container.Runtime.ContainerID)
	publisher.cgroupIDField.PutUint64(ev, container.CgroupID)
	publisher.mountNsIDField.PutUint64(ev, container.Mntns)
	if k8s {
		publisher.nameField.PutString(ev, container.K8s.ContainerName)
	} else {
		publisher.nameField.PutString(ev, container.Runtime.ContainerName)
	}

	publisher.containerConfigField.PutString(ev, container.OciConfig)
	publisher.pidField.PutUint32(ev, container.ContainerPid())

	err = publisher.containersDs.EmitAndRelease(ev)
	if err != nil {
		return fmt.Errorf("emitting containers datasource event: %w", err)
	}

	return nil
}

func (publisher *ContainersPublisher) PublishContainers(k8s bool, extraContainers []*containercollection.Container, containerSelector containercollection.ContainerSelector) error {
	var containers []*containercollection.Container

	if publisher.collection != nil {
		publisher.containersSubscriptionKey = uuid.New().String()

		log.Debugf("add datasource containers subscription to container collection")
		containers = publisher.collection.Subscribe(
			publisher.containersSubscriptionKey,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				err := publisher.emitContainersDatasourceEvent(event.Type, event.Container, k8s)
				if err != nil {
					log.Errorf("publishing new container event: %v", err)
				}
			},
		)
	}

	if len(extraContainers) > 0 {
		containers = append(containers, extraContainers...)
	}

	for _, container := range containers {
		err := publisher.emitContainersDatasourceEvent(containercollection.EventTypeAddContainer, container, k8s)
		if err != nil {
			return fmt.Errorf("publishing existing container event: %w", err)
		}
	}

	return nil
}

func (publisher *ContainersPublisher) Unsubscribe() {
	if publisher.containersSubscriptionKey != "" {
		publisher.collection.Unsubscribe(publisher.containersSubscriptionKey)
	}
}
