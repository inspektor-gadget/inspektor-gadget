// Copyright 2022-2025 The Inspektor Gadget authors
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
	"github.com/cilium/ebpf/rlimit"
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	OperatorName           = "LocalManager"
	Runtimes               = "runtimes"
	Host                   = "host"
	DockerSocketPath       = "docker-socketpath"
	ContainerdSocketPath   = "containerd-socketpath"
	CrioSocketPath         = "crio-socketpath"
	PodmanSocketPath       = "podman-socketpath"
	ContainerdNamespace    = "containerd-namespace"
	RuntimeProtocol        = "runtime-protocol"
	EnrichWithK8sApiserver = "enrich-with-k8s-apiserver"
	KubeconfigPath         = "kubeconfig"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type localManager struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection

	fakeContainer *containercollection.Container
}

func (l *localManager) Name() string {
	return OperatorName
}

func (l *localManager) Description() string {
	return "Handles enrichment of container data and attaching/detaching to and from containers"
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
		{
			Key:          KubeconfigPath,
			DefaultValue: "", // Try in-cluster config by default
			Description:  "Path to kubeconfig file. If not set, in-cluster config will be used.",
		},
	}
}

func (l *localManager) ParamDescs() params.ParamDescs {
	return append(common.GetContainerSelectorParams(false),
		&params.ParamDesc{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		})
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

	kubeconfig := operatorParams.Get(KubeconfigPath).AsString()
	enrichWithK8s := operatorParams.Get(EnrichWithK8sApiserver).AsBool()
	if err := l.initCollections(rc, kubeconfig, enrichWithK8s); err != nil {
		log.Warnf("Failed to create container-collection")
		log.Debugf("Failed to create container-collection: %s", err)
	}

	return nil
}

// initCollections initializes the container collection and tracer collection.
func (l *localManager) initCollections(rc []*containerutilsTypes.RuntimeConfig, kubeconfig string, enrichWithK8s bool) error {
	var cc containercollection.ContainerCollection

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	var err error
	l.tracerCollection, err = tracercollection.NewTracerCollection(&cc)
	if err != nil {
		return fmt.Errorf("creating tracer collection: %w", err)
	}

	// Initialization options for the container collection
	ccOpts := []containercollection.ContainerCollectionOption{}

	if !log.IsLevelEnabled(log.DebugLevel) && isDefaultContainerRuntimeConfig(rc) {
		// If requested, WithDisableContainerRuntimeWarnings needs to be set
		// before WithMultipleContainerRuntimesEnrichment.
		warnings := []containercollection.ContainerCollectionOption{containercollection.WithDisableContainerRuntimeWarnings()}
		ccOpts = append(ccOpts, warnings...)
	}

	ccOpts = append(ccOpts, []containercollection.ContainerCollectionOption{
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithMultipleContainerRuntimesEnrichment(rc),
		containercollection.WithOCIConfigForInitialContainer(),
		containercollection.WithContainerFanotifyEbpf(),
		containercollection.WithTracerCollection(l.tracerCollection),
		containercollection.WithProcEnrichment(),
	}...)

	if kubeconfig != "" {
		ccOpts = append(ccOpts, containercollection.WithKubeconfigPath(kubeconfig))
	}

	if enrichWithK8s {
		nodeName := os.Getenv("NODE_NAME")
		if nodeName == "" {
			return errors.New("NODE_NAME environment variable is not set, cannot enrich with K8s API server")
		}
		ccOpts = append(ccOpts, containercollection.WithNodeName(nodeName))
		ccOpts = append(ccOpts, containercollection.WithKubernetesEnrichment(nodeName))
	}

	err = cc.Initialize(ccOpts...)
	if err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	l.containerCollection = &cc

	return nil
}

func (l *localManager) Close() error {
	if l.containerCollection != nil {
		l.containerCollection.Close()
	}
	if l.tracerCollection != nil {
		l.tracerCollection.Close()
	}
	return nil
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

	if l.gadgetInstance != nil {
		err := l.handleGadgetInstance(log)
		if err != nil {
			return err
		}
	}

	return nil
}

func (l *localManagerTrace) handleGadgetInstance(log logger.Logger) error {
	id := uuid.New()
	host := l.params.Get(Host).AsBool()

	containerSelector := common.NewContainerSelector(l.params)

	// If --host is set, we do not want to create the below map because we do not
	// want any filtering.
	if setter, ok := l.gadgetInstance.(MountNsMapSetter); ok {
		if !host {
			if l.manager.containerCollection == nil {
				return fmt.Errorf("container-collection isn't available")
			}

			id := id.String()
			if err := l.manager.tracerCollection.AddTracer(id, containerSelector); err != nil {
				return fmt.Errorf("adding tracer %q: %w", id, err)
			}

			// Create mount namespace map to filter by containers
			mountnsmap, err := l.manager.tracerCollection.TracerMountNsMap(id)
			if err != nil {
				l.manager.tracerCollection.RemoveTracer(id)
				return fmt.Errorf("getting mount namespace map for tracer %q: %w", id, err)
			}

			log.Debugf("set mountnsmap for gadget")
			setter.SetMountNsMap(mountnsmap)

			l.mountnsmap = mountnsmap
		} else if l.manager.containerCollection == nil {
			log.Warn("container-collection isn't available: container enrichment and filtering won't work")
		}
	}

	if attacher, ok := l.gadgetInstance.(Attacher); ok {
		if l.manager.containerCollection == nil {
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

		if l.manager.containerCollection != nil {
			l.subscriptionKey = id.String()
			log.Debugf("add subscription to containerCollection")
			containers = l.manager.containerCollection.Subscribe(
				l.subscriptionKey,
				containerSelector,
				func(event containercollection.PubSubEvent) {
					log.Debugf("%s: %s", event.Type.String(), event.Container.Runtime.ContainerID)
					switch event.Type {
					case containercollection.EventTypeAddContainer:
						attachContainerFunc(event.Container)
					case containercollection.EventTypeRemoveContainer:
						detachContainerFunc(event.Container)
					case containercollection.EventTypePreCreateContainer:
						// nothing to do
					default:
						log.Errorf("unknown event type, expected either %s, %s or %s, got %s",
							containercollection.EventTypePreCreateContainer,
							containercollection.EventTypeAddContainer,
							containercollection.EventTypeRemoveContainer,
							event.Type)
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
		l.manager.tracerCollection.RemoveTracer(l.subscriptionKey)
	}
	if l.subscriptionKey != "" {
		host := l.params.Get(Host).AsBool()

		log.Debugf("calling Unsubscribe()")
		l.manager.containerCollection.Unsubscribe(l.subscriptionKey)

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
		l.manager.containerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		l.manager.containerCollection.EnrichEventByNetNs(event)
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
		if l.containerCollection == nil {
			return nil, fmt.Errorf("container-collection isn't available, but containers datasource is enabled")
		}

		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, l.containerCollection)
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
	return append(common.GetContainerSelectorParams(false),
		&params.ParamDesc{
			Key:          Host,
			Description:  "Show data from both the host and containers",
			DefaultValue: "false",
			TypeHint:     params.TypeBool,
		})
}

func (l *localManager) Priority() int {
	return -1
}

func (l *localManagerTraceWrapper) PreStart(gadgetCtx operators.GadgetContext) error {
	l.gadgetInstance, _ = gadgetCtx.GetVar("ebpfInstance")

	if l.manager.containerCollection != nil {
		compat.Subscribe(
			l.eventWrappers,
			l.manager.containerCollection.EnrichEventByMntNs,
			l.manager.containerCollection.EnrichEventByNetNs,
			0,
		)
	}

	id := uuid.New()
	host := l.params.Get(Host).AsBool()

	containerSelector := common.NewContainerSelector(l.params)

	// mountnsmap will be handled differently than above
	if !host {
		if l.manager.containerCollection == nil {
			return fmt.Errorf("container-collection isn't available")
		}

		id := id.String()
		if err := l.manager.tracerCollection.AddTracer(id, containerSelector); err != nil {
			return fmt.Errorf("adding tracer %q: %w", id, err)
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := l.manager.tracerCollection.TracerMountNsMap(id)
		if err != nil {
			l.manager.tracerCollection.RemoveTracer(id)
			return fmt.Errorf("getting mount namespace map for tracer %q: %w", id, err)
		}

		gadgetCtx.Logger().Debugf("set mountnsmap for gadget")
		gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)
		gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)

		l.mountnsmap = mountnsmap
	} else if l.manager.containerCollection == nil {
		log.Warn("container-collection isn't available: container enrichment and filtering won't work")
	}

	return l.PreGadgetRun()
}

func (l *localManagerTraceWrapper) Start(gadgetCtx operators.GadgetContext) error {
	if l.containersPublisher == nil {
		return nil
	}

	host := l.params.Get(Host).AsBool()
	containerSelector := common.NewContainerSelector(l.params)

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

	return nil
}

func (l *localManagerTraceWrapper) Close(gadgetCtx operators.GadgetContext) error {
	return l.PostGadgetRun()
}

func isDefaultContainerRuntimeConfig(runtimes []*containerutilsTypes.RuntimeConfig) bool {
	if len(runtimes) != len(containerutils.AvailableRuntimes) {
		return false
	}

	var customSocketPath bool
	for _, runtime := range runtimes {
		switch runtime.Name {
		case types.RuntimeNameDocker:
			customSocketPath = runtime.SocketPath != runtimeclient.DockerDefaultSocketPath
		case types.RuntimeNameContainerd:
			customSocketPath = runtime.SocketPath != runtimeclient.ContainerdDefaultSocketPath
		case types.RuntimeNameCrio:
			customSocketPath = runtime.SocketPath != runtimeclient.CrioDefaultSocketPath
		case types.RuntimeNamePodman:
			customSocketPath = runtime.SocketPath != runtimeclient.PodmanDefaultSocketPath
		default:
			customSocketPath = true
		}
		if customSocketPath {
			return false
		}
	}

	return true
}

func init() {
	lm := &localManager{}
	operators.RegisterDataOperator(lm)
}

var LocalManagerOperator = &localManager{}
