// Copyright 2023-2025 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	hookservice "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service"
	hookserviceapi "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
)

const (
	OperatorName = "KubeManager"

	// Global parameter keys
	ParamHookMode               = "hook-mode"
	ParamFallbackPodInformer    = "fallback-podinformer"
	ParamHookLivenessSocketFile = "hook-liveness-socketfile"

	// Instance parameter keys
	ParamAllNamespaces = "all-namespaces"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type KubeManager struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
}

func (k *KubeManager) Name() string {
	return OperatorName
}

func (k *KubeManager) Description() string {
	return "KubeManager handles container/pod/namespace information using Container-Collection and Tracer-Collection."
}

func (k *KubeManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamFallbackPodInformer,
			DefaultValue: "true",
			Description:  "Use pod informer as a fallback for the main hook",
			TypeHint:     params.TypeBool,
		},
		{
			Key:            ParamHookMode,
			DefaultValue:   hookModeAuto,
			Description:    "Mechanism to collect container information",
			TypeHint:       params.TypeString,
			PossibleValues: supportedHookModes,
		},
		{
			Key:          ParamHookLivenessSocketFile,
			DefaultValue: types.DefaultHookAndLivenessSocketFile,
			Description:  "Path to the socket file for serving hook's requests for adding/removing containers and for liveness checks",
			TypeHint:     params.TypeString,
		},
	}
}

func (k *KubeManager) ParamDescs() params.ParamDescs {
	return append(common.GetContainerSelectorParams(true),
		&params.ParamDesc{
			Key:          ParamAllNamespaces,
			Alias:        "A",
			Description:  "Show data from pods in all namespaces",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		})
}

func (k *KubeManager) Init(params *params.Params) error {
	hookMode := params.Get(ParamHookMode).AsString()
	fallbackPodInformer := params.Get(ParamFallbackPodInformer).AsBool()
	socketPath := params.Get(ParamHookLivenessSocketFile).AsString()

	var err error
	hookMode, err = parseHookMode(hookMode)
	if err != nil {
		return fmt.Errorf("parsing hook mode: %w", err)
	}

	if err := k.initCollections(hookMode, fallbackPodInformer); err != nil {
		return fmt.Errorf("initializing collections: %w", err)
	}

	// Start the gRPC server for the hook service and health checks
	grpcServer := grpc.NewServer()
	os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	// Register the hook service to handle container add/remove requests
	hookServer := hookservice.NewServer(k.containerCollection)
	hookserviceapi.RegisterHookServiceServer(grpcServer, hookServer)

	// Register the health server to handle health checks
	healthServer := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthServer)

	log.Printf("Serving hook-service and health-checks on %s", socketPath)
	go grpcServer.Serve(listener)

	return nil
}

// initCollections initializes the container collection and tracer collection.
func (k *KubeManager) initCollections(hookMode string, fallbackPodInformer bool) error {
	var cc containercollection.ContainerCollection

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	node := os.Getenv("NODE_NAME")
	if node == "" {
		return fmt.Errorf("environment variable NODE_NAME not set")
	}

	var err error
	k.tracerCollection, err = tracercollection.NewTracerCollection(&cc)
	if err != nil {
		return fmt.Errorf("creating tracer collection: %w", err)
	}

	// Initialize ContainerCollection with the options
	ccOpts := []containercollection.ContainerCollectionOption{
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithNodeName(node),
		containercollection.WithKubernetesEnrichment(node),
		containercollection.WithTracerCollection(k.tracerCollection),
		containercollection.WithProcEnrichment(),
	}

	hookModeOpts, err := hookMode2ccOpts(node, hookMode, fallbackPodInformer)
	if err != nil {
		return fmt.Errorf("getting extra container collection options: %w", err)
	}
	ccOpts = append(ccOpts, hookModeOpts...)

	err = cc.Initialize(ccOpts...)
	if err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	k.containerCollection = &cc

	return nil
}

func (k *KubeManager) Close() error {
	return nil
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

	eventWrappers map[datasource.DataSource]*compat.EventWrapperBase

	containersPublisher *common.ContainersPublisher
}

func (m *KubeManagerInstance) Name() string {
	return OperatorName
}

func (m *KubeManagerInstance) PreGadgetRun() error {
	log := m.gadgetCtx.Logger()

	if m.gadgetInstance != nil {
		err := m.handleGadgetInstance(log)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *KubeManagerInstance) handleGadgetInstance(log logger.Logger) error {
	containerSelector := newContainerSelector(m.params)

	if setter, ok := m.gadgetInstance.(MountNsMapSetter); ok {
		err := m.manager.tracerCollection.AddTracer(m.id, containerSelector)
		if err != nil {
			return fmt.Errorf("adding tracer: %w", err)
		}

		// Create mount namespace map to filter by containers
		mountnsmap, err := m.manager.tracerCollection.TracerMountNsMap(m.id)
		if err != nil {
			m.manager.tracerCollection.RemoveTracer(m.id)
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
				var ve *ebpf.VerifierError
				if errors.As(err, &ve) {
					m.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", container.K8s.ContainerName, ve)
				}

				log.Warnf("start tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}

			m.attachedContainers[container.Runtime.ContainerID] = container

			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			delete(m.attachedContainers, container.Runtime.ContainerID)

			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", container.K8s.ContainerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				container.K8s.ContainerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		m.subscribed = true

		log.Debugf("add subscription to containerCollection")
		containers := m.manager.containerCollection.Subscribe(
			m.id,
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

		for _, container := range containers {
			attachContainerFunc(container)
		}
	}
	return nil
}

func newContainerSelector(params *params.Params) containercollection.ContainerSelector {
	containerSelector := common.NewContainerSelector(params)
	if params.Get(ParamAllNamespaces).AsBool() {
		containerSelector.K8s.Namespace = ""
	}
	return containerSelector
}

func (m *KubeManagerInstance) PostGadgetRun() error {
	if m.mountnsmap != nil {
		m.gadgetCtx.Logger().Debugf("calling RemoveTracer()")
		m.manager.tracerCollection.RemoveTracer(m.id)
	}

	if m.subscribed {
		m.gadgetCtx.Logger().Debugf("calling Unsubscribe()")
		m.manager.containerCollection.Unsubscribe(m.id)

		// emit detach for all remaining containers
		for _, container := range m.attachedContainers {
			m.attacher.DetachContainer(container)
		}
	}

	return nil
}

func (m *KubeManagerInstance) enrich(ev any) {
	if event, canEnrichEventFromMountNs := ev.(operators.ContainerInfoFromMountNSID); canEnrichEventFromMountNs {
		m.manager.containerCollection.EnrichEventByMntNs(event)
	}
	if event, canEnrichEventFromNetNs := ev.(operators.ContainerInfoFromNetNSID); canEnrichEventFromNetNs {
		m.manager.containerCollection.EnrichEventByNetNs(event)
	}
}

func (m *KubeManagerInstance) EnrichEvent(ev any) error {
	if !m.enrichEvents {
		return nil
	}
	m.enrich(ev)
	return nil
}

func (k *KubeManager) GlobalParams() api.Params {
	return apihelpers.ParamDescsToParams(k.GlobalParamDescs())
}

func (k *KubeManager) InstanceParams() api.Params {
	return apihelpers.ParamDescsToParams(k.ParamDescs())
}

func (k *KubeManager) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	params := k.ParamDescs().ToParams()
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
		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, k.containerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating containers publisher: %w", err)
		}
	}

	traceInstance := &KubeManagerInstance{
		manager:            k,
		enrichEvents:       false,
		attachedContainers: make(map[string]*containercollection.Container),
		params:             params,
		gadgetCtx:          gadgetCtx,
		id:                 uuid.New().String(),

		eventWrappers: make(map[datasource.DataSource]*compat.EventWrapperBase),

		containersPublisher: containersPublisher,
	}

	activate := false

	// Check, whether the gadget requested a map from us
	if t, ok := gadgetCtx.GetVar(gadgets.MntNsFilterMapName); ok {
		if _, ok := t.(*ebpf.Map); ok {
			gadgetCtx.Logger().Debugf("gadget requested map %s", gadgets.MntNsFilterMapName)
			activate = true
		}
	}

	// Check for NeedContainerEvents; this is set for example for tchandlers, as they
	// require the Attacher interface to be aware of containers
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

func (k *KubeManager) Priority() int {
	return -1
}

func (m *KubeManagerInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	m.gadgetInstance, _ = gadgetCtx.GetVar("ebpfInstance")

	compat.Subscribe(
		m.eventWrappers,
		m.manager.containerCollection.EnrichEventByMntNs,
		m.manager.containerCollection.EnrichEventByNetNs,
		0,
	)

	containerSelector := newContainerSelector(m.params)

	if m.manager.containerCollection == nil {
		return fmt.Errorf("container-collection isn't available")
	}

	// Create mount namespace map to filter by containers
	err := m.manager.tracerCollection.AddTracer(m.id, containerSelector)
	if err != nil {
		return fmt.Errorf("adding tracer: %w", err)
	}

	mountnsmap, err := m.manager.tracerCollection.TracerMountNsMap(m.id)
	if err != nil {
		m.manager.tracerCollection.RemoveTracer(m.id)
		return fmt.Errorf("creating mountnsmap: %w", err)
	}

	gadgetCtx.Logger().Debugf("set mountnsmap for gadget")
	gadgetCtx.SetVar(gadgets.MntNsFilterMapName, mountnsmap)
	gadgetCtx.SetVar(gadgets.FilterByMntNsName, true)

	m.mountnsmap = mountnsmap
	// using PreGadgetRun() for the time being to register attacher funcs
	return m.PreGadgetRun()
}

func (m *KubeManagerInstance) Start(gadgetCtx operators.GadgetContext) error {
	if m.containersPublisher == nil {
		return nil
	}

	containerSelector := newContainerSelector(m.params)

	return m.containersPublisher.PublishContainers(true, []*containercollection.Container{}, containerSelector)
}

func (m *KubeManagerInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *KubeManagerInstance) Close(gadgetCtx operators.GadgetContext) error {
	m.manager.tracerCollection.RemoveTracer(m.id)

	if m.containersPublisher != nil {
		m.containersPublisher.Unsubscribe()
	}

	return nil
}

var KubeManagerOperator *KubeManager

func init() {
	KubeManagerOperator = &KubeManager{}
	operators.RegisterDataOperator(KubeManagerOperator)
}
