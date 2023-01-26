// Copyright 2022-2023 The Inspektor Gadget authors
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

package localmanager

import (
	"errors"
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	"github.com/inspektor-gadget/inspektor-gadget/internal/operators"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName  = "LocalManager"
	Runtimes      = "runtimes"
	ContainerName = "containername"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type ContainersMapSetter interface {
	SetContainersMap(*ebpf.Map)
}

type Attacher interface {
	AttachGeneric(container *containercollection.Container, handler any) error
	DetachGeneric(*containercollection.Container) error
}

type LocalManager struct {
	localGadgetManager *localgadgetmanager.LocalGadgetManager
	rc                 []*containerutils.RuntimeConfig
}

func (l *LocalManager) Name() string {
	return OperatorName
}

func (l *LocalManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers"
}

func (l *LocalManager) Dependencies() []string {
	return nil
}

func (l *LocalManager) Params() params.Params {
	return params.Params{
		{
			Key:          Runtimes,
			Alias:        "r",
			DefaultValue: strings.Join(containerutils.AvailableRuntimes, ","),
			Description: fmt.Sprintf("Container runtimes to be used separated by comma. Supported values are: %s",
				strings.Join(containerutils.AvailableRuntimes, ", ")),
			IsMandatory: true,
			// PossibleValues: containerutils.AvailableRuntimes, // TODO
		},
	}
}

func (l *LocalManager) PerGadgetParams() params.Params {
	return params.Params{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			IsMandatory: false,
		},
	}
}

func (l *LocalManager) CanOperateOn(gadget gadgets.Gadget) bool {
	// We need to be able to get MountNSID and set ContainerInfo, so check for that first
	_, canEnrichEvent := gadget.EventPrototype().(operators.KubernetesFromMountNSID)

	// Secondly, we need to be able to inject the ebpf map onto the tracer
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		log.Printf("cannot instantiate")
		return false
	}

	instance, err := gi.NewInstance(nil)
	if err != nil {
		log.Printf("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)
	_, isContainersMapSetter := instance.(ContainersMapSetter)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)
	log.Debugf("> isContainersMapSetter: %v", isContainersMapSetter)

	return (isMountNsMapSetter && canEnrichEvent) || isAttacher || isContainersMapSetter
}

func (l *LocalManager) Init(operatorParams params.Params) error {
	pm := operatorParams.ParamMap()
	runtimes := pm[Runtimes]

	rc := make([]*containerutils.RuntimeConfig, 0)
	parts := strings.Split(runtimes, ",")

partsLoop:
	for _, p := range parts {
		runtimeName := strings.TrimSpace(p)
		socketPath := ""

		switch runtimeName {
		case runtimeclient.DockerName:
			// socketPath = commonFlags.RuntimesSocketPathConfig.Docker
		case runtimeclient.ContainerdName:
			// socketPath = commonFlags.RuntimesSocketPathConfig.Containerd
		case runtimeclient.CrioName:
			// socketPath = commonFlags.RuntimesSocketPathConfig.Crio
		default:
			return commonutils.WrapInErrInvalidArg("--runtime / -r",
				fmt.Errorf("runtime %q is not supported", p))
		}

		for _, r := range rc {
			if r.Name == runtimeName {
				log.Infof("Ignoring duplicated runtime %q from %q",
					runtimeName, runtimes)
				continue partsLoop
			}
		}

		rc = append(rc, &containerutils.RuntimeConfig{
			Name:       runtimeName,
			SocketPath: socketPath,
		})
	}

	l.rc = rc

	localGadgetManager, err := localgadgetmanager.NewManager(l.rc)
	if err != nil {
		return commonutils.WrapInErrManagerInit(err)
	}
	l.localGadgetManager = localGadgetManager
	return nil
}

func (l *LocalManager) Cleanup() error {
	l.localGadgetManager.Close()
	return nil
}

type LocalManagerTrace struct {
	*LocalManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers, so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
}

func (l *LocalManager) PreGadgetRun(runner operators.Runner, tracer any, perGadgetParams params.Params) (operators.Operator, error) {
	_, canEnrichEvent := runner.Gadget().EventPrototype().(operators.KubernetesFromMountNSID)

	log := runner.Logger()

	traceInstance := &LocalManagerTrace{
		LocalManager:       l,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
	}

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Name: perGadgetParams.Get(ContainerName).AsString(),
	}

	if setter, ok := tracer.(MountNsMapSetter); ok {
		// Create mount namespace map to filter by containers
		mountnsmap, err := l.localGadgetManager.CreateMountNsMap(containerSelector)
		if err != nil {
			return nil, commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		traceInstance.mountnsmap = mountnsmap
	}

	if setter, ok := tracer.(ContainersMapSetter); ok {
		setter.SetContainersMap(l.localGadgetManager.ContainersMap())
	}

	if attacher, ok := tracer.(Attacher); ok {
		traceInstance.attacher = attacher

		attachContainerFunc := func(container *containercollection.Container) {
			var cbFunc any

			if runner.Columns() != nil {
				cbFunc = runner.Columns().EventHandlerFunc(runner.Operators().Enrich, func(a any) {
					if !container.HostNetwork {
						s := a.(operators.ContainerInfoSetters)
						s.SetContainerInfo(container.Podname, container.Namespace, container.Name)
					}
				})
			}

			log.Debugf("calling gadget.AttachGeneric()")
			err := attacher.AttachGeneric(container, cbFunc)
			if err != nil {
				// TODO: return oob
				// msg := fmt.Sprintf("start tracing container %q: %s", container.Name, err)
				// eventCallback(container, base(eventtypes.Err(msg)))
				log.Warnf("attach: %v", err)
				return
			}

			traceInstance.attachedContainers[container] = struct{}{}

			// TODO: return oob
			log.Debugf("tracer attached")
			// eventCallback(container, base(eventtypes.Debug("tracer attached")))
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			err := attacher.DetachGeneric(container)
			if err != nil {
				// TODO: return oob
				// msg := fmt.Sprintf("stop tracing container %q: %s", container.Name, err)
				// eventCallback(container, base(eventtypes.Err(msg)))
				log.Warnf("detach: %v", err)
				return
			}
			// TODO: return oob
			log.Debugf("tracer detached")
			// eventCallback(container, base(eventtypes.Debug("tracer detached")))
		}

		id := uuid.New()
		traceInstance.subscriptionKey = id.String()

		log.Debugf("add subscription")
		containers := l.localGadgetManager.Subscribe(
			traceInstance.subscriptionKey,
			containerSelector,
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
	}

	return traceInstance, nil
}

func (l *LocalManagerTrace) PostGadgetRun() error {
	l.LocalManager.PostGadgetRun()

	if l.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		l.localGadgetManager.RemoveMountNsMap()
	}
	if l.subscriptionKey != "" {
		log.Debugf("calling Unsubscribe()")
		l.localGadgetManager.Unsubscribe(l.subscriptionKey)

		// emit detach for all remaining containers
		for container := range l.attachedContainers {
			l.attacher.DetachGeneric(container)
		}
	}
	return nil
}

func (l *LocalManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}

	event, ok := ev.(operators.KubernetesFromMountNSID)
	if !ok {
		return errors.New("invalid event to enrich")
	}
	l.localGadgetManager.ContainerCollection.EnrichEvent(event)

	container := l.localGadgetManager.ContainerCollection.LookupContainerByMntns(event.GetMountNSID())
	if container != nil {
		event.SetContainerInfo(container.Podname, container.Namespace, container.Name)
	}
	return nil
}

func (l *LocalManager) PostGadgetRun() error {
	return nil
}

func (l *LocalManager) EnrichEvent(a any) error {
	return nil
}

func init() {
	operators.RegisterOperator(&LocalManager{})
}
