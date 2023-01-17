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
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	localgadgetmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/local-gadget-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName         = "LocalManager"
	OperatorInstanceName = "LocalManagerTrace"
	Runtimes             = "runtimes"
	ContainerName        = "containername"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type ContainersMapSetter interface {
	SetContainersMap(*ebpf.Map)
}

type Attacher interface {
	AttachGeneric(container *containercollection.Container) error
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

func (l *LocalManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
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

func (l *LocalManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			IsMandatory: false,
		},
	}
}

func (l *LocalManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// We need to be able to get MountNSID and set ContainerInfo, so check for that first
	_, canEnrichEvent := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)

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

func (l *LocalManager) Init(operatorParams *params.Params) error {
	rc := make([]*containerutils.RuntimeConfig, 0)
	parts := operatorParams.Get(Runtimes).AsStringSlice()

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
				log.Infof("Ignoring duplicated runtime %q from %v",
					runtimeName, parts)
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

func (l *LocalManager) Close() error {
	l.localGadgetManager.Close()
	return nil
}

func (l *LocalManager) Instantiate(gadgetContext operators.GadgetContext, tracer any, params *params.Params) (operators.OperatorInstance, error) {
	_, canEnrichEvent := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)

	traceInstance := &localManagerTrace{
		LocalManager:       l,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
		params:             params,
		tracer:             tracer,
		gadgetCtx:          gadgetContext,
	}

	return traceInstance, nil
}

type localManagerTrace struct {
	*LocalManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers, so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
	params             *params.Params
	tracer             any
	gadgetCtx          operators.GadgetContext
}

func (l *localManagerTrace) Name() string {
	return OperatorInstanceName
}

func (l *localManagerTrace) PreGadgetRun() error {
	log := l.gadgetCtx.Logger()

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Name: l.params.Get(ContainerName).AsString(),
	}

	if setter, ok := l.tracer.(MountNsMapSetter); ok {
		// Create mount namespace map to filter by containers
		mountnsmap, err := l.localGadgetManager.CreateMountNsMap(containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		l.mountnsmap = mountnsmap
	}

	if setter, ok := l.tracer.(ContainersMapSetter); ok {
		setter.SetContainersMap(l.localGadgetManager.ContainersMap())
	}

	if attacher, ok := l.tracer.(Attacher); ok {
		l.attacher = attacher

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachGeneric()")
			err := attacher.AttachGeneric(container)
			if err != nil {
				log.Warnf("start tracing container %q: %s", container.Name, err)
				return
			}

			l.attachedContainers[container] = struct{}{}

			log.Debugf("tracer attached") // TODO: container info?
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			err := attacher.DetachGeneric(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.Name, err)
				return
			}
			log.Debugf("tracer detached") // TODO: container info?
		}

		id := uuid.New()
		l.subscriptionKey = id.String()

		log.Debugf("add subscription")
		containers := l.localGadgetManager.Subscribe(
			l.subscriptionKey,
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

func (l *localManagerTrace) PostGadgetRun() error {
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

func (l *localManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}
	return l.localGadgetManager.ContainerCollection.EnrichEvent(ev)
}

func (l *localManagerTrace) Enricher(next operators.EnricherFunc) operators.EnricherFunc {
	if !l.enrichEvents {
		return nil
	}
	return func(ev any) error {
		err := l.localGadgetManager.ContainerCollection.EnrichEvent(ev)
		if err != nil {
			return err
		}
		return next(ev)
	}
}

func init() {
	operators.Register(&LocalManager{})
}
