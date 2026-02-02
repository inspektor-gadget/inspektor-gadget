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

package ecsmanager

import (
	"errors"
	"fmt"
	"os"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
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
)

const (
	OperatorName = "EcsManager"

	// Global parameter keys
	ParamEcsClusterName = "ecs-cluster-name"
	ParamAwsRegion      = "aws-region"

	// Instance parameter keys
	ParamAllServices = "all-services"
)

type MountNsMapSetter interface {
	SetMountNsMap(*ebpf.Map)
}

type Attacher interface {
	AttachContainer(container *containercollection.Container) error
	DetachContainer(*containercollection.Container) error
}

type EcsManager struct {
	containerCollection *containercollection.ContainerCollection
	tracerCollection    *tracercollection.TracerCollection
}

func (e *EcsManager) Name() string {
	return OperatorName
}

func (e *EcsManager) Description() string {
	return "EcsManager handles container/task/service information for AWS ECS workloads using Container-Collection and Tracer-Collection."
}

func (e *EcsManager) GlobalParamDescs() params.ParamDescs {
	return params.ParamDescs{
		{
			Key:          ParamEcsClusterName,
			DefaultValue: "",
			Description:  "ECS cluster name or ARN to monitor",
			TypeHint:     params.TypeString,
		},
		{
			Key:          ParamAwsRegion,
			DefaultValue: "",
			Description:  "AWS region where the ECS cluster is located",
			TypeHint:     params.TypeString,
		},
	}
}

func (e *EcsManager) ParamDescs() params.ParamDescs {
	return append(common.GetContainerSelectorParams(false),
		&params.ParamDesc{
			Key:          ParamAllServices,
			Alias:        "A",
			Description:  "Show data from containers in all ECS services",
			TypeHint:     params.TypeBool,
			DefaultValue: "false",
		})
}

func (e *EcsManager) Init(params *params.Params) error {
	clusterName := params.Get(ParamEcsClusterName).AsString()
	awsRegion := params.Get(ParamAwsRegion).AsString()

	if clusterName == "" {
		// Try to get from environment variable as fallback
		clusterName = os.Getenv("ECS_CLUSTER_NAME")
	}
	if awsRegion == "" {
		// Try to get from environment variable as fallback
		awsRegion = os.Getenv("AWS_REGION")
	}

	if err := e.initCollections(clusterName, awsRegion); err != nil {
		return fmt.Errorf("initializing collections: %w", err)
	}

	return nil
}

// initCollections initializes the container collection and tracer collection.
func (e *EcsManager) initCollections(clusterName, awsRegion string) error {
	var cc containercollection.ContainerCollection

	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("removing memlock rlimit: %w", err)
	}

	// For ECS, we don't need NODE_NAME like Kubernetes
	// We'll use cluster name as the node identifier
	nodeName := clusterName
	if nodeName == "" {
		nodeName = "ecs-cluster"
	}

	var err error
	e.tracerCollection, err = tracercollection.NewTracerCollection(&cc)
	if err != nil {
		return fmt.Errorf("creating tracer collection: %w", err)
	}

	// Initialize ContainerCollection with the options
	ccOpts := []containercollection.ContainerCollectionOption{
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithNodeName(nodeName),
		containercollection.WithTracerCollection(e.tracerCollection),
		containercollection.WithProcEnrichment(),
		containercollection.WithEcsEnrichment(clusterName, awsRegion),
	}

	err = cc.Initialize(ccOpts...)
	if err != nil {
		return fmt.Errorf("initializing container collection: %w", err)
	}

	e.containerCollection = &cc

	log.Infof("EcsManager initialized for cluster: %s, region: %s", clusterName, awsRegion)

	return nil
}

func (e *EcsManager) Close() error {
	return nil
}

type EcsManagerInstance struct {
	id           string
	manager      *EcsManager
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

func (m *EcsManagerInstance) Name() string {
	return OperatorName
}

func (m *EcsManagerInstance) PreGadgetRun() error {
	log := m.gadgetCtx.Logger()

	if m.gadgetInstance != nil {
		err := m.handleGadgetInstance(log)
		if err != nil {
			return err
		}
	}

	return nil
}

func (m *EcsManagerInstance) handleGadgetInstance(log logger.Logger) error {
	containerSelector := newEcsContainerSelector(m.params)

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
				containerName := container.Runtime.ContainerName
				if container.Ecs.ContainerName != "" {
					containerName = container.Ecs.ContainerName
				}
				if errors.As(err, &ve) {
					m.gadgetCtx.Logger().Debugf("start tracing container %q: verifier error: %+v\n", containerName, ve)
				}

				log.Warnf("start tracing container %q: %s", containerName, err)
				return
			}

			m.attachedContainers[container.Runtime.ContainerID] = container

			containerName := container.Runtime.ContainerName
			if container.Ecs.ContainerName != "" {
				containerName = container.Ecs.ContainerName
			}
			log.Debugf("tracer attached: container %q pid %d mntns %d netns %d",
				containerName, container.ContainerPid(), container.Mntns, container.Netns)
		}

		detachContainerFunc := func(container *containercollection.Container) {
			log.Debugf("calling gadget.Detach()")
			delete(m.attachedContainers, container.Runtime.ContainerID)

			containerName := container.Runtime.ContainerName
			if container.Ecs.ContainerName != "" {
				containerName = container.Ecs.ContainerName
			}
			err := attacher.DetachContainer(container)
			if err != nil {
				log.Warnf("stop tracing container %q: %s", containerName, err)
				return
			}
			log.Debugf("tracer detached: container %q pid %d mntns %d netns %d",
				containerName, container.ContainerPid(), container.Mntns, container.Netns)
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

func newEcsContainerSelector(params *params.Params) containercollection.ContainerSelector {
	containerSelector := common.NewContainerSelector(params)

	// Add ECS-specific filtering
	allServices := params.Get(ParamAllServices).AsBool()
	if allServices {
		// Empty cluster/service name means match all
		containerSelector.Ecs.ClusterName = ""
		containerSelector.Ecs.ServiceName = ""
	} else {
		// For now, we'll filter by cluster name if provided
		// Service name filtering can be added later as a parameter
		// The actual ECS metadata will be populated by the discovery engine
	}

	return containerSelector
}

func (m *EcsManagerInstance) PostGadgetRun() error {
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

func (e *EcsManager) GlobalParams() api.Params {
	return apihelpers.ParamDescsToParams(e.GlobalParamDescs())
}

func (e *EcsManager) InstanceParams() api.Params {
	return apihelpers.ParamDescsToParams(e.ParamDescs())
}

func (e *EcsManager) InstantiateDataOperator(gadgetCtx operators.GadgetContext, paramValues api.ParamValues) (
	operators.DataOperatorInstance, error,
) {
	params := e.ParamDescs().ToParams()
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
		containersPublisher, err = common.NewContainersPublisher(gadgetCtx, e.containerCollection)
		if err != nil {
			return nil, fmt.Errorf("creating containers publisher: %w", err)
		}
	}

	traceInstance := &EcsManagerInstance{
		manager:            e,
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

func (e *EcsManager) Priority() int {
	return -1
}

func (m *EcsManagerInstance) PreStart(gadgetCtx operators.GadgetContext) error {
	m.gadgetInstance, _ = gadgetCtx.GetVar("ebpfInstance")

	compat.Subscribe(
		m.eventWrappers,
		m.manager.containerCollection.EnrichEventByMntNs,
		m.manager.containerCollection.EnrichEventByNetNs,
		0,
	)

	containerSelector := newEcsContainerSelector(m.params)

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

func (m *EcsManagerInstance) Start(gadgetCtx operators.GadgetContext) error {
	if m.containersPublisher == nil {
		return nil
	}

	containerSelector := newEcsContainerSelector(m.params)

	return m.containersPublisher.PublishContainers(true, []*containercollection.Container{}, containerSelector)
}

func (m *EcsManagerInstance) Stop(gadgetCtx operators.GadgetContext) error {
	return nil
}

func (m *EcsManagerInstance) Close(gadgetCtx operators.GadgetContext) error {
	m.manager.tracerCollection.RemoveTracer(m.id)

	if m.containersPublisher != nil {
		m.containersPublisher.Unsubscribe()
	}

	return nil
}

var EcsManagerOperator *EcsManager

func init() {
	EcsManagerOperator = &EcsManager{}
	operators.RegisterDataOperator(EcsManagerOperator)
}
