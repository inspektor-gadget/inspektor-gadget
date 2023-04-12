// Copyright 2023 The Inspektor Gadget authors
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

package kubemanager

import (
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName       = "KubeManager"
	ParamContainerName = "containername"
	ParamSelector      = "selector"
	ParamAllNamespaces = "all-namespaces"
	ParamPodName       = "podname"
	ParamNamespace     = "namespace"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type KubeManager struct {
	gadgetTracerManager *gadgettracermanager.GadgetTracerManager
}

func (k *KubeManager) SetGadgetTracerMgr(g *gadgettracermanager.GadgetTracerManager) {
	log.Infof("gadget tracermgr set in kubemanager")
	k.gadgetTracerManager = g
}

func (k *KubeManager) Name() string {
	return OperatorName
}

func (k *KubeManager) Description() string {
	return "KubeManager handles container/pod/namespace information using Container-Collection and GadgetTracerMgr"
}

func (k *KubeManager) GlobalParamDescs() params.ParamDescs {
	return nil
}

func (k *KubeManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ParamContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.K8SContainerName,
		},
		{
			Key:         ParamSelector,
			Alias:       "l",
			Description: "Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2).",
			ValueHint:   gadgets.K8SLabels,
			Validator: func(value string) error {
				if value == "" {
					return nil
				}

				pairs := strings.Split(value, ",")
				for _, pair := range pairs {
					kv := strings.Split(pair, "=")
					if len(kv) != 2 {
						return fmt.Errorf("should be a comma-separated list of key-value pairs (key=value[,key=value,...])")
					}
				}

				return nil
			},
		},
		{
			Key:         ParamPodName,
			Alias:       "p",
			Description: "Show only data from pods with that name",
			ValueHint:   gadgets.K8SPodName,
		},
		{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		},
		{
			Key:         ParamNamespace,
			Alias:       "n",
			Description: "Show only data from pods in a given namespace",
			ValueHint:   gadgets.K8SNamespace,
		},
	}
}

func (k *KubeManager) Dependencies() []string {
	return nil
}

func (k *KubeManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// We need to be able to get MountNSID or NetNSID, and set ContainerInfo, so
	// check for that first
	_, canEnrichEventFromMountNs := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadget.EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	// Secondly, we need to be able to inject the ebpf map onto the tracer
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Warn("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf(" > canEnrichEventFromMountNs: %v", canEnrichEventFromMountNs)
	log.Debugf(" > canEnrichEventFromNetNs: %v", canEnrichEventFromNetNs)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)

	return (isMountNsMapSetter && canEnrichEvent) || isAttacher
}

func (k *KubeManager) Init(params *params.Params) error {
	return nil
}

func (k *KubeManager) Close() error {
	return nil
}

func (k *KubeManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	_, canEnrichEventFromMountNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	traceInstance := &KubeManagerInstance{
		id:             uuid.New().String(),
		manager:        k,
		enrichEvents:   canEnrichEvent,
		params:         params,
		gadgetInstance: gadgetInstance,
		gadgetCtx:      gadgetContext,
	}

	return traceInstance, nil
}

type KubeManagerInstance struct {
	id           string
	manager      *KubeManager
	enrichEvents bool
	mountnsmap   *ebpf.Map
	subscribed   bool

	attachedContainers map[string]*containercollection.Container
	attacher           Attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext
}

func (m *KubeManagerInstance) Name() string {
	return "KubeManagerInstance"
}

func (m *KubeManagerInstance) PreGadgetRun() error {
	log := m.gadgetCtx.Logger()

	labels := make(map[string]string)
	selectorSlice := m.params.Get(ParamSelector).AsStringSlice()
	for _, pair := range selectorSlice {
		kv := strings.Split(pair, "=")
		labels[kv[0]] = kv[1]
	}

	containerSelector := containercollection.ContainerSelector{
		Namespace: m.params.Get(ParamNamespace).AsString(),
		Podname:   m.params.Get(ParamPodName).AsString(),
		Name:      m.params.Get(ParamContainerName).AsString(),
		Labels:    labels,
	}

	if m.params.Get(ParamAllNamespaces).AsBool() {
		containerSelector.Namespace = ""
	}

	if setter, ok := m.gadgetInstance.(MountNsMapSetter); ok {
		err := m.manager.gadgetTracerManager.AddTracer(m.id, containerSelector)
		if err != nil {
			return fmt.Errorf("adding tracer: %w", err)
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := m.manager.gadgetTracerManager.TracerMountNsMap(m.id)
		if err != nil {
			m.manager.gadgetTracerManager.RemoveTracer(m.id)
			return fmt.Errorf("creating mountns map: %w", err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		m.mountnsmap = mountnsmap
	}

	if attacher, ok := m.gadgetInstance.(Attacher); ok {
		m.attacher = attacher
		m.attachedContainers = make(map[string]*containercollection.Container)

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				log.Warnf("start tracing container %q: %s", container.Name, err)
				return
			}

			m.attachedContainers[container.ID] = container

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			delete(m.attachedContainers, container.ID)

			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.Name, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		m.subscribed = true

		log.Debugf("add subscription")
		containers := m.manager.gadgetTracerManager.Subscribe(
			m.id,
			containerSelector,
			func(event containercollection.PubSubEvent) {
				log.Debugf("%s: %s", event.Type.String(), event.Container.ID)
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
	}

	return nil
}

func (m *KubeManagerInstance) PostGadgetRun() error {
	if m.mountnsmap != nil {
		m.gadgetCtx.Logger().Debugf("calling RemoveTracer()")
		m.manager.gadgetTracerManager.RemoveTracer(m.id)
	}
	if m.subscribed {
		m.gadgetCtx.Logger().Debugf("calling Unsubscribe()")
		m.manager.gadgetTracerManager.Unsubscribe(m.id)

		// emit detach for all remaining containers
		for _, container := range m.attachedContainers {
			m.attacher.DetachContainer(container)
		}
	}
	return nil
}

func (m *KubeManagerInstance) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		m.manager.gadgetTracerManager.ContainerCollection.EnrichEventByNetNs(event)
	}
}

func (m *KubeManagerInstance) EnrichEvent(ev any) error {
	if !m.enrichEvents {
		return nil
	}
	m.enrich(ev)
	return nil
}

func init() {
	operators.Register(&KubeManager{})
}
