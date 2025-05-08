// Copyright 2022-2024 The Inspektor Gadget authors
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
	"os"
	"slices"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/containerd/containerd/pkg/cri/constants"
	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	commonutils "github.com/inspektor-gadget/inspektor-gadget/cmd/common/utils"
	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	runtimeclient "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/runtime-client"
	containerutilsTypes "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	igmanager "github.com/inspektor-gadget/inspektor-gadget/pkg/ig-manager"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	OperatorName           = "LocalManager"
	Runtimes               = "runtimes"
	ContainerName          = "containername"
	Host                   = "host"
	DockerSocketPath       = "docker-socketpath"
	ContainerdSocketPath   = "containerd-socketpath"
	CrioSocketPath         = "crio-socketpath"
	PodmanSocketPath       = "podman-socketpath"
	ContainerdNamespace    = "containerd-namespace"
	RuntimeProtocol        = "runtime-protocol"
	EnrichWithK8sApiserver = "enrich-with-k8s-apiserver"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type localManager struct {
	igManager     *igmanager.IGManager
	rc            []*containerutilsTypes.RuntimeConfig
	fakeContainer *containercollection.Container
}

func (l *localManager) Name() string {
	return OperatorName
}

func (l *localManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers"
}

func (l *localManager) Dependencies() []string {
	return nil
}

func (l *localManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          Runtimes,
			Alias:        "r",
			DefaultValue: strings.Join(containerutils.AvailableRuntimes, ","),
			Description: fmt.Sprintf("Comma-separated list of container runtimes. Supported values are: %s",
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
		{
			Key:          ContainerdNamespace,
			DefaultValue: constants.K8sContainerdNamespace,
			Description:  "Containerd namespace to use",
		},
		{
			Key:          RuntimeProtocol,
			DefaultValue: "internal",
			Description:  "Container runtime protocol. Supported values are: internal, cri",
		},
		{
			Key:          EnrichWithK8sApiserver,
			DefaultValue: "false",
			Description:  "Connect to the K8s API server to get further K8s enrichment",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *localManager) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
		{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *localManager) CanOperateOn(gadget gadgets.GadgetDesc) bool {
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
		log.Warnf("failed to create dummy %s instance: %s", OperatorName, err)
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

func (l *localManager) Init(operatorParams *params.Params) error {
	rc := make([]*containerutilsTypes.RuntimeConfig, 0)

	runtimesParam := operatorParams.Get(Runtimes)
	runtimesIsSet := runtimesParam.IsSet()
	runtimes := runtimesParam.AsStringSlice()
	slices.Sort(runtimes)
	runtimes = slices.Compact(runtimes)

	for _, runtime := range runtimes {
		runtimeName := types.String2RuntimeName(strings.TrimSpace(runtime))
		namespace := ""

		var socketPathParam *params.Param

		switch runtimeName {
		case types.RuntimeNameDocker:
			socketPathParam = operatorParams.Get(DockerSocketPath)
		case types.RuntimeNameContainerd:
			socketPathParam = operatorParams.Get(ContainerdSocketPath)
			namespace = operatorParams.Get(ContainerdNamespace).AsString()
		case types.RuntimeNameCrio:
			socketPathParam = operatorParams.Get(CrioSocketPath)
		case types.RuntimeNamePodman:
			socketPathParam = operatorParams.Get(PodmanSocketPath)
		default:
			return commonutils.WrapInErrInvalidArg("--runtime / -r",
				fmt.Errorf("runtime %q is not supported", runtime))
		}

		socketPath := socketPathParam.AsString()
		socketPathIsSet := socketPathParam.IsSet()

		cleanSocketPath, err := securejoin.SecureJoin(host.HostRoot, socketPath)
		if err != nil {
			log.Debugf("securejoin failed: %s", err)
			continue
		}

		if _, err := os.Stat(cleanSocketPath); err != nil {
			if socketPathIsSet || runtimesIsSet {
				return fmt.Errorf("runtime %q with non-existent socketPath %q", runtimeName, socketPath)
			}
			log.Debugf("Ignoring runtime %q with non-existent socketPath %q", runtimeName, socketPath)
			continue
		}

		r := &containerutilsTypes.RuntimeConfig{
			Name:            runtimeName,
			SocketPath:      cleanSocketPath,
			RuntimeProtocol: operatorParams.Get(RuntimeProtocol).AsString(),
			Extra: containerutilsTypes.ExtraConfig{
				Namespace: namespace,
			},
		}

		rc = append(rc, r)
	}

	l.rc = rc

	pidOne := uint32(1)
	mntns, err := containerutils.GetMntNs(int(pidOne))
	if err != nil {
		return fmt.Errorf("getting mount namespace ID for host PID %d: %w", pidOne, err)
	}

	// We need this fake container for gadget which rely only on the Attacher
	// concept:
	// * Network gadget will get the netns corresponding to PID 1 on their
	//   own.
	// * Others, like traceloop or advise seccomp-profile, need the mount
	//   namespace ID to bet set.
	l.fakeContainer = &containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: types.BasicRuntimeMetadata{
				ContainerPID: pidOne,
			},
		},
		Mntns: mntns,
	}

	additionalOpts := []containercollection.ContainerCollectionOption{}
	if operatorParams.Get(EnrichWithK8sApiserver).AsBool() {
		additionalOpts = append(additionalOpts, containercollection.WithKubernetesEnrichment("", nil))
	}

	igManager, err := igmanager.NewManager(l.rc, additionalOpts)
	if err != nil {
		log.Warnf("Failed to create container-collection")
		log.Debugf("Failed to create container-collection: %s", err)
	}
	l.igManager = igManager
	return nil
}

func (l *localManager) Close() error {
	if l.igManager != nil {
		l.igManager.Close()
	}
	return nil
}

func (l *localManager) Instantiate(gadgetContext operators.GadgetContext, gadgetInstance any, params *params.Params) (operators.OperatorInstance, error) {
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

	if l.igManager == nil {
		traceInstance.enrichEvents = false
	}

	return traceInstance, nil
}

type localManagerTrace struct {
	manager         *localManager
	mountnsmap      *ebpf.Map
	enrichEvents    bool
	subscriptionKey string

	// Keep a map to attached containers, so we can clean up properly
	attachedContainers map[*containercollection.Container]struct{}
	attacher           Attacher
	params             *params.Params
	gadgetInstance     any
	gadgetCtx          operators.GadgetContext

	eventWrappers map[datasource.DataSource]*compat.EventWrapperBase

	containersPublisher *common.ContainersPublisher
}

func (l *localManagerTrace) Name() string {
	return OperatorName
}

func (l *localManagerTrace) PreGadgetRun() error {
	log := l.gadgetCtx.Logger()
	id := uuid.New()
	host := l.params.Get(Host).AsBool()

	// TODO: Improve filtering, see further details in
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/644.
	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: l.params.Get(ContainerName).AsString(),
		},
	}

	// If --host is set, we do not want to create the below map because we do not
	// want any filtering.
	if setter, ok := l.gadgetInstance.(MountNsMapSetter); ok {
		if !host {
			if l.manager.igManager == nil {
				return fmt.Errorf("container-collection isn't available")
			}

			// Create mount namespace map to filter by containers
			mountnsmap, err := l.manager.igManager.CreateMountNsMap(id.String(), containerSelector)
			if err != nil {
				return commonutils.WrapInErrManagerCreateMountNsMap(err)
			}

			log.Debugf("set mountnsmap for gadget")
			setter.SetMountNsMap(mountnsmap)

			l.mountnsmap = mountnsmap
		} else if l.manager.igManager == nil {
			log.Warn("container-collection isn't available: container enrichment and filtering won't work")
		}
	}

	if attacher, ok := l.gadgetInstance.(Attacher); ok {
		if l.manager.igManager == nil {
			if !host {
				return fmt.Errorf("container-collection isn't available")
			}

			log.Warn("container-collection isn't available: no containers will be traced")
		}

		l.attacher = attacher
		var containers []*containercollection.Container

		attachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.AttachContainer()")
			err := attacher.AttachContainer(container)
			if err != nil {
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					l.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", container.K8s.ContainerName, ve)
				}

				log.Warnf("start tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}

			l.attachedContainers[container] = struct{}{}

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.DetachContainer()")
			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		if l.manager.igManager != nil {
			l.subscriptionKey = id.String()
			log.Debugf("add subscription to igManager")
			containers = l.manager.igManager.Subscribe(
				l.subscriptionKey,
				containerSelector,
				func(event containercollection.PubSubEvent) {
					log.Debugf("%s: %s", event.Type.String(), event.Container.Runtime.ContainerID)
					switch event.Type {
					case containercollection.EventTypeAddContainer:
						attachContainerFunc(event.Container)
					case containercollection.EventTypeRemoveContainer:
						detachContainerFunc(event.Container)
					default:
						log.Errorf("unknown event type, expected either %s or %s, got %s", containercollection.EventTypeAddContainer, containercollection.EventTypeRemoveContainer, event.Type)
						return
					}
				},
			)
		}

		if host {
			containers = append(containers, l.manager.fakeContainer)
		}

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}

	return nil
}

func (l *localManagerTrace) PostGadgetRun() error {
	if l.mountnsmap != nil {
		log.Debugf("calling RemoveMountNsMap()")
		l.manager.igManager.RemoveMountNsMap(l.subscriptionKey)
	}
	if l.subscriptionKey != "" {
		host := l.params.Get(Host).AsBool()

		log.Debugf("calling Unsubscribe()")
		l.manager.igManager.Unsubscribe(l.subscriptionKey)

		if l.attacher != nil {
			// emit detach for all remaining containers
			for container := range l.attachedContainers {
				l.attacher.DetachContainer(container)
			}

			if host {
				l.attacher.DetachContainer(l.manager.fakeContainer)
			}
		}
	}
	return nil
}

func (l *localManagerTrace) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		l.manager.igManager.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		l.manager.igManager.EnrichEventByNetNs(event)
	}
}

func (l *localManagerTrace) EnrichEvent(ev any) error {
	if !l.enrichEvents {
		return nil
	}
	l.enrich(ev)
	return nil
}

type localManagerTraceWrapper struct {
	localManagerTrace
	runID string
}

func (l *localManager) GlobalParams() api.Params {
	return apihelpers.ParamDescsToParams(l.GlobalParamDescs())
}

func (l *localManager) InstanceParams() api.Params {
	return apihelpers.ParamDescsToParams(l.ParamDescs())
}

func (l *localManager) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	params := l.ParamDescs().ToParams()
	err := params.CopyFromMap(paramValues, "")
	if err != nil {
		return nil, err
	}

	cfg, ok := gadgetCtx.GetVar("config")
	if !ok {
		return nil, fmt.Errorf("missing configuration")
	}
	v, ok := cfg.(*viper.Viper)
	if !ok {
		return nil, fmt.Errorf("invalid configuration format")
	}

	enableContainersDs := v.GetBool("annotations.enable-containers-datasource")

	var containersPublisher *common.ContainersPublisher
	if enableContainersDs {
		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, &l.igManager.ContainerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating containers publisher: %w", err)
		}
	}

	// Wrapper is used to have ParamDescs() with the new signature
	traceInstance := &localManagerTraceWrapper{
		localManagerTrace: localManagerTrace{
			manager:            l,
			enrichEvents:       false,
			attachedContainers: make(map[*containercollection.Container]struct{}),
			params:             params,
			gadgetCtx:          gadgetCtx,

			eventWrappers: make(map[datasource.DataSource]*compat.EventWrapperBase),

			containersPublisher: containersPublisher,
		},
	}

	activate := false

	// Check, whether the gadget requested a map from us
	if t, ok := gadgetCtx.GetVar(gadgets.MntNsFilterMapName); ok {
		if _, ok := t.(*ebpf.Map); ok {
			gadgetCtx.Logger().Debugf("gadget requested map %s", gadgets.MntNsFilterMapName)
			activate = true
		}
	}

	// Check for override - currently needed for tchandlers
	if val, ok := gadgetCtx.GetVar("NeedContainerEvents"); ok {
		if b, ok := val.(bool); ok && b {
			activate = true
		}
	}

	wrappers, err := compat.GetEventWrappers(gadgetCtx)
	if err != nil {
		return nil, fmt.Errorf("getting event wrappers: %w", err)
	}
	traceInstance.eventWrappers = wrappers
	if len(wrappers) > 0 {
		activate = true
	}

	if !activate {
		return nil, nil
	}

	return traceInstance, nil
}

func (l *localManagerTrace) ParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:         ContainerName,
			Alias:       "c",
			Description: "Show only data from containers with that name",
			ValueHint:   gadgets.LocalContainer,
		},
		{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		},
	}
}

func (l *localManagerTraceWrapper) ParamDescs(gadgetCtx operators.GadgetContext) params.ParamDescs {
	return l.localManagerTrace.ParamDescs()
}

func (l *localManager) Priority() int {
	return -1
}

func (l *localManagerTraceWrapper) PreStart(gadgetCtx operators.GadgetContext) error {
	// hack - this makes it possible to use the Attacher interface
	var ok bool
	l.gadgetInstance, ok = gadgetCtx.GetVar("ebpfInstance")
	if !ok {
		return fmt.Errorf("getting ebpfInstance")
	}

	if l.manager.igManager != nil {
		compat.Subscribe(
			l.eventWrappers,
			l.manager.igManager.EnrichEventByMntNs,
			l.manager.igManager.EnrichEventByNetNs,
			0,
		)
	}

	id := uuid.New()
	host := l.params.Get(Host).AsBool()

	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: l.params.Get(ContainerName).AsString(),
		},
	}

	// mountnsmap will be handled differently than above
	if !host {
		if l.manager.igManager == nil {
			return fmt.Errorf("container-collection isn't available")
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := l.manager.igManager.CreateMountNsMap(id.String(), containerSelector)
		if err != nil {
			return commonutils.WrapInErrManagerCreateMountNsMap(err)
		}

		gadgetCtx.Logger().Debugf("set mountnsmap for gadget")
		gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)
		gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)

		l.mountnsmap = mountnsmap
	} else if l.manager.igManager == nil {
		log.Warn("container-collection isn't available: container enrichment and filtering won't work")
	}

	return l.PreGadgetRun()
}

func (l *localManagerTraceWrapper) Start(gadgetCtx operators.GadgetContext) error {
	if l.containersPublisher == nil {
		return nil
	}

	host := l.params.Get(Host).AsBool()
	containerSelector := containercollection.ContainerSelector{
		Runtime: containercollection.RuntimeSelector{
			ContainerName: l.params.Get(ContainerName).AsString(),
		},
	}

	extraContainers := []*containercollection.Container{}
	if host {
		extraContainers = append(extraContainers, l.manager.fakeContainer)
	}

	return l.containersPublisher.PublishContainers(false, extraContainers, containerSelector)
}

func (l *localManagerTraceWrapper) Stop(gadgetCtx operators.GadgetContext) error {
	if l.containersPublisher != nil {
		l.containersPublisher.Unsubscribe()
	}

	return l.PostGadgetRun()
}

func init() {
	lm := &localManager{}
	operators.Register(lm)
	operators.RegisterDataOperator(lm)
}

var LocalManagerOperator = &localManager{}
