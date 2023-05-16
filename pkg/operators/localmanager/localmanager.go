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
	igmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/ig-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

const (
	OperatorName         = "LocalManager"
	OperatorInstanceName = "LocalManagerTrace"
	Runtimes             = "runtimes"
	ContainerName        = "containername"
	DockerSocketPath     = "docker-socketpath"
	ContainerdSocketPath = "containerd-socketpath"
	CrioSocketPath       = "crio-socketpath"
	PodmanSocketPath     = "podman-socketpath"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type LocalManager struct {
	igManager *igmanager.IGManager
	rc        []*containerutils.RuntimeConfig
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
			// PossibleValues: containerutils.AvailableRuntimes, // TODO
		},
		{
			Key:          DockerSocketPath,
			DefaultValue: runtimeclient.DockerDefaultSocketPath,
			Description:  "Docker Engine API Unix socket path",
		},
		{
			Key:          ContainerdSocketPath,
			DefaultValue: runtimeclient.ContainerdDefaultSocketPath,
			Description:  "Containerd CRI Unix socket path",
		},
		{
			Key:          CrioSocketPath,
			DefaultValue: runtimeclient.CrioDefaultSocketPath,
			Description:  "CRI-O CRI Unix socket path",
		},
		{
			Key:          PodmanSocketPath,
			DefaultValue: runtimeclient.PodmanDefaultSocketPath,
			Description:  "Podman Unix socket path",
		},
	}
}

func (l *LocalManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
	}
}

func (l *LocalManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
	// We need to be able to get MountNSID or NetNSID, and set ContainerInfo, so
	// check for that first
	_, canEnrichEventFromMountNs := gadget.EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadget.EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	// Secondly, we need to be able to inject the ebpf map onto the gadget instance
	gi, ok := gadget.(gadgets.GadgetInstantiate)
	if !ok {
		return false
	}

	instance, err := gi.NewInstance()
	if err != nil {
		log.Printf("failed to create dummy instance")
		return false
	}
	_, isMountNsMapSetter := instance.(MountNsMapSetter)
	_, isAttacher := instance.(Attacher)

	log.Debugf("> canEnrichEvent: %v", canEnrichEvent)
	log.Debugf("\t> canEnrichEventFromMountNs: %v", canEnrichEventFromMountNs)
	log.Debugf("\t> canEnrichEventFromNetNs: %v", canEnrichEventFromNetNs)
	log.Debugf("> isMountNsMapSetter: %v", isMountNsMapSetter)
	log.Debugf("> isAttacher: %v", isAttacher)

	return isMountNsMapSetter || canEnrichEvent || isAttacher
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
			socketPath = operatorParams.Get(DockerSocketPath).AsString()
		case runtimeclient.ContainerdName:
			socketPath = operatorParams.Get(ContainerdSocketPath).AsString()
		case runtimeclient.CrioName:
			socketPath = operatorParams.Get(CrioSocketPath).AsString()
		case runtimeclient.PodmanName:
			socketPath = operatorParams.Get(PodmanSocketPath).AsString()
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

	igManager, err := igmanager.NewManager(l.rc)
	if err != nil {
		return commonutils.WrapInErrManagerInit(err)
	}
	l.igManager = igManager
	return nil
}

func (l *LocalManager) Close() error {
	l.igManager.Close()
	return nil
}

func (l *LocalManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
	_, canEnrichEventFromMountNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromMountNSID)
	_, canEnrichEventFromNetNs := gadgetContext.GadgetDesc().EventPrototype().(operators.ContainerInfoFromNetNSID)
	canEnrichEvent := canEnrichEventFromMountNs || canEnrichEventFromNetNs

	traceInstance := &localManagerTrace{
		manager:            l,
		enrichEvents:       canEnrichEvent,
		attachedContainers: make(map[*containercollection.Container]struct{}),
		params:             params,
		gadgetInstance:     gadgetInstance,
		gadgetCtx:          gadgetContext,
	}

	return traceInstance, nil
}

type localManagerTrace struct {
	manager         *LocalManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers, so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
	params             *params.Params
	gadgetInstance     any
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

	if setter, ok := l.gadgetInstance.(MountNsMapSetter); ok {
		// Create mount namespace map to filter by containers
		mountnsmap, err := l.manager.igManager.CreateMountNsMap(containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		log.Debugf("set mountnsmap for gadget")
		setter.SetMountNsMap(mountnsmap)

		l.mountnsmap = mountnsmap
	}

	if attacher, ok := l.gadgetInstance.(Attacher); ok {
		l.attacher = attacher

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				log.Warnf("start tracing container %q: %s", container.Name, err)
				return
			}

			l.attachedContainers[container] = struct{}{}

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.DetachContainer()")
			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.Name, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.Name, container.Pid, container.Mntns, container.Netns)
		}

		id := uuid.New()
		l.subscriptionKey = id.String()

		log.Debugf("add subscription")
		containers := l.manager.igManager.Subscribe(
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
		l.manager.igManager.RemoveMountNsMap()
	}
	if l.subscriptionKey != "" {
		log.Debugf("calling Unsubscribe()")
		l.manager.igManager.Unsubscribe(l.subscriptionKey)

		// emit detach for all remaining containers
		for container := range l.attachedContainers {
			l.attacher.DetachContainer(container)
		}
	}
	return nil
}

func (l *localManagerTrace) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		l.manager.igManager.ContainerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		l.manager.igManager.ContainerCollection.EnrichEventByNetNs(event)
	}
}

func (l *localManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}
	l.enrich(ev)
	return nil
}

func init() {
	operators.Register(&LocalManager{})
}
