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
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	nriv1 "github.com/containerd/nri/types/v1"
	"github.com/google/uuid"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/viper"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/compat"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	containersmap "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators/common"
	hookservice "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service"
	hookserviceapi "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/kubemanager/hook-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	OperatorName = "KubeManager"

	// Instance parameter keys
	ParamContainerName = "containername"
	ParamSelector      = "selector"
	ParamAllNamespaces = "all-namespaces"
	ParamPodName       = "podname"
	ParamNamespace     = "namespace"

	// Global parameter keys
	ParamHookMode            = "hook-mode"
	ParamFallbackPodInformer = "fallback-podinformer"
	ParamSocketFile          = "socketfile"

	// Hook modes
	HookModeNone         = "none"
	HookModeAuto         = "auto"
	HookModeCrio         = "crio"
	HookModeNRI          = "nri"
	HookModePodInformer  = "podinformer"
	HookModeFanotifyEbpf = "fanotify+ebpf"

	// Defaults for parameters
	defaultSocketFile = "/run/hook-service.socket"
	defaultHookMode   = HookModeAuto
)

var supportedHookModes = []string{
	HookModeAuto,
	HookModeCrio,
	HookModeNRI,
	HookModePodInformer,
	HookModeFanotifyEbpf,
}

var crioRegex = regexp.MustCompile(`1:name=systemd:.*/crio-[0-9a-f]*\.scope`)

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
	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
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
			DefaultValue:   defaultHookMode,
			Description:    "Mechanism to collect container information",
			TypeHint:       params.TypeString,
			PossibleValues: supportedHookModes,
		},
		{
			Key:          ParamSocketFile,
			DefaultValue: defaultSocketFile,
			Description:  "Path to the socket file for serving hook's requests for adding/removing containers",
			TypeHint:     params.TypeString,
		},
	}
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

func copyFile(destination, source string, filemode fs.FileMode) error {
	content, err := os.ReadFile(source)
	if err != nil {
		return fmt.Errorf("reading %s: %w", source, err)
	}

	info, err := os.Stat(destination)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("stat'ing %s: %w", destination, err)
	}

	if info != nil && info.IsDir() {
		destination = filepath.Join(destination, filepath.Base(source))
	}

	err = os.WriteFile(destination, content, filemode)
	if err != nil {
		return fmt.Errorf("writing %s: %w", destination, err)
	}

	return nil
}

func installCRIOHooks() error {
	log.Info("Installing hooks scripts on host...")

	path := filepath.Join(host.HostRoot, "opt/hooks/oci")
	err := os.MkdirAll(path, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", path, err)
	}

	for _, file := range []string{"ocihookgadget", "prestart.sh", "poststop.sh"} {
		log.Infof("Installing %s", file)

		path := filepath.Join("/opt/hooks/oci", file)
		destinationPath := filepath.Join(host.HostRoot, path)
		err := copyFile(destinationPath, path, 0o750)
		if err != nil {
			return fmt.Errorf("copying: %w", err)
		}
	}

	for _, file := range []string{"etc/containers/oci/hooks.d", "usr/share/containers/oci/hooks.d/"} {
		hookPath := filepath.Join(host.HostRoot, file)

		log.Infof("Installing OCI hooks configuration in %s", hookPath)
		err := os.MkdirAll(hookPath, 0o755)
		if err != nil {
			return fmt.Errorf("creating hook path %s: %w", path, err)
		}
		errCount := 0
		for _, config := range []string{"/opt/hooks/crio/gadget-prestart.json", "/opt/hooks/crio/gadget-poststop.json"} {
			err := copyFile(hookPath, config, 0o640)
			if err != nil {
				errCount++
			}
		}

		if errCount != 0 {
			log.Warn("Couldn't install OCI hooks configuration")
		} else {
			log.Info("Hooks installation done")
		}
	}

	return nil
}

func installNRIHooks() error {
	log.Info("Installing NRI hooks")

	destinationPath := filepath.Join(host.HostRoot, "opt/nri/bin")
	err := os.MkdirAll(destinationPath, 0o755)
	if err != nil {
		return fmt.Errorf("creating %s: %w", destinationPath, err)
	}

	err = copyFile(destinationPath, "/opt/hooks/nri/nrigadget", 0o640)
	if err != nil {
		return fmt.Errorf("copying: %w", err)
	}

	hostConfigPath := filepath.Join(host.HostRoot, "etc/nri/conf.json")
	content, err := os.ReadFile(hostConfigPath)
	if err == nil {
		var configList nriv1.ConfigList

		err := json.Unmarshal(content, &configList)
		if err != nil {
			return fmt.Errorf("unmarshalling JSON %s: %w", hostConfigPath, err)
		}

		configList.Plugins = append(configList.Plugins, &nriv1.Plugin{Type: "nrigadget"})

		content, err = json.Marshal(configList)
		if err != nil {
			return fmt.Errorf("marshalling JSON: %w", err)
		}

		err = os.WriteFile(hostConfigPath, content, 0o640)
		if err != nil {
			return fmt.Errorf("writing %s: %w", hostConfigPath, err)
		}
	} else {
		destinationPath := filepath.Join(host.HostRoot, "etc/nri")
		err = os.MkdirAll(destinationPath, 0o755)
		if err != nil {
			return fmt.Errorf("creating %s: %w", destinationPath, err)
		}

		err := copyFile(destinationPath, "/opt/hooks/nri/conf.json", 0o640)
		if err != nil {
			return fmt.Errorf("copying: %w", err)
		}
	}

	return nil
}

func parseHookMode(hookMode string) (string, error) {
	path := "/proc/self/cgroup"
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}

	crio := false
	if crioRegex.Match(content) {
		log.Infof("CRI-O detected.")
		crio = true
	}

	if (hookMode == HookModeAuto) && crio {
		log.Info("Hook mode CRI-O detected")
		hookMode = HookModeCrio
	}

	switch hookMode {
	case HookModeCrio:
		err := installCRIOHooks()
		if err != nil {
			return "", fmt.Errorf("installing CRIO hooks: %w", err)
		}
	case HookModeNRI:
		err := installNRIHooks()
		if err != nil {
			return "", fmt.Errorf("installing NRI hooks: %w", err)
		}
	}

	parsedHookMode := HookModeAuto
	switch hookMode {
	case HookModeCrio, HookModeNRI:
		parsedHookMode = HookModeNone
	case HookModeFanotifyEbpf, HookModePodInformer:
		parsedHookMode = hookMode
	}

	log.Infof("Parsed hook mode: %s", parsedHookMode)

	return parsedHookMode, nil
}

func (k *KubeManager) Init(params *params.Params) error {
	hookMode := params.Get(ParamHookMode).AsString()
	fallbackPodInformer := params.Get(ParamFallbackPodInformer).AsBool()
	socketPath := params.Get(ParamSocketFile).AsString()

	var err error
	hookMode, err = parseHookMode(hookMode)
	if err != nil {
		return fmt.Errorf("parsing hook mode: %w", err)
	}

	if err := k.initCollections(hookMode, fallbackPodInformer); err != nil {
		return fmt.Errorf("initializing collections: %w", err)
	}

	service := hookservice.New(k.containerCollection)

	var opts []grpc.ServerOption
	grpcServer := grpc.NewServer(opts...)

	os.Remove(socketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return fmt.Errorf("listening on %s: %w", socketPath, err)
	}

	hookserviceapi.RegisterHookServiceServer(grpcServer, service)

	healthserver := health.NewServer()
	healthpb.RegisterHealthServer(grpcServer, healthserver)

	log.Printf("Serving HookService on %s", socketPath)
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
		log.Fatal("Environment variable NODE_NAME not set")
	}

	var err error
	k.tracerCollection, err = tracercollection.NewTracerCollection(&cc)
	if err != nil {
		return fmt.Errorf("creating tracer collection: %w", err)
	}

	// TODO: Do we still need the containers map?
	k.containersMap, err = containersmap.NewContainersMap("")
	if err != nil {
		return fmt.Errorf("creating containers map: %w", err)
	}

	// Initialize ContainerCollection with the options
	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(k.containersMap.ContainersMapUpdater()),
		containercollection.WithOCIConfigEnrichment(),
		containercollection.WithCgroupEnrichment(),
		containercollection.WithLinuxNamespaceEnrichment(),
		containercollection.WithKubernetesEnrichment(node),
		containercollection.WithTracerCollection(k.tracerCollection),
		containercollection.WithProcEnrichment(),
	}

	podInformerUsed := false
	switch hookMode {
	case "none":
		// Used by nri and crio: They will call the hook-service directly to add and remove container
		log.Infof("KubeManager: hook mode: none")
		opts = append(opts, containercollection.WithInitialKubernetesContainers(node))
		opts = append(opts, containercollection.WithOCIConfigForInitialContainer())
	case "auto":
		if containerhook.Supported() {
			log.Infof("KubeManager: hook mode: fanotify+ebpf (auto)")
			opts = append(opts, containercollection.WithContainerFanotifyEbpf())
			opts = append(opts, containercollection.WithInitialKubernetesContainers(node))
			opts = append(opts, containercollection.WithOCIConfigForInitialContainer())
		} else {
			log.Infof("KubeManager: hook mode: podinformer (auto)")
			opts = append(opts, containercollection.WithPodInformer(node))
			podInformerUsed = true
		}
	case "podinformer":
		log.Infof("KubeManager: hook mode: podinformer")
		opts = append(opts, containercollection.WithPodInformer(node))
		podInformerUsed = true
	case "fanotify+ebpf":
		log.Infof("KubeManager: hook mode: fanotify+ebpf")
		opts = append(opts, containercollection.WithContainerFanotifyEbpf())
		opts = append(opts, containercollection.WithInitialKubernetesContainers(node))
		opts = append(opts, containercollection.WithOCIConfigForInitialContainer())
	default:
		return fmt.Errorf("invalid hook mode: %s", hookMode)
	}

	if fallbackPodInformer && !podInformerUsed {
		log.Infof("KubeManager: enabling fallback podinformer")
		opts = append(opts, containercollection.WithFallbackPodInformer(node))
	}

	err = cc.Initialize(opts...)
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

func newContainerSelector(selectorSlice []string, namespace, podName, containerName string, useAllNamespace bool) containercollection.ContainerSelector {
	labels := make(map[string]string)
	for _, pair := range selectorSlice {
		kv := strings.Split(pair, "=")
		labels[kv[0]] = kv[1]
	}

	containerSelector := containercollection.ContainerSelector{
		K8s: containercollection.K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     namespace,
				PodName:       podName,
				ContainerName: containerName,
				PodLabels:     labels,
			},
		},
	}

	if useAllNamespace {
		containerSelector.K8s.Namespace = ""
	}

	return containerSelector
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
	containerSelector := newContainerSelector(
		m.params.Get(ParamSelector).AsStringSlice(),
		m.params.Get(ParamNamespace).AsString(),
		m.params.Get(ParamPodName).AsString(),
		m.params.Get(ParamContainerName).AsString(),
		m.params.Get(ParamAllNamespaces).AsBool(),
	)

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

	labels := make(map[string]string)
	selectorSlice := m.params.Get(ParamSelector).AsStringSlice()
	for _, pair := range selectorSlice {
		kv := strings.Split(pair, "=")
		labels[kv[0]] = kv[1]
	}

	containerSelector := containercollection.ContainerSelector{
		K8s: containercollection.K8sSelector{
			BasicK8sMetadata: types.BasicK8sMetadata{
				Namespace:     m.params.Get(ParamNamespace).AsString(),
				PodName:       m.params.Get(ParamPodName).AsString(),
				ContainerName: m.params.Get(ParamContainerName).AsString(),
				PodLabels:     labels,
			},
		},
	}

	if m.params.Get(ParamAllNamespaces).AsBool() {
		containerSelector.K8s.Namespace = ""
	}

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

	containerSelector := newContainerSelector(
		m.params.Get(ParamSelector).AsStringSlice(),
		m.params.Get(ParamNamespace).AsString(),
		m.params.Get(ParamPodName).AsString(),
		m.params.Get(ParamContainerName).AsString(),
		m.params.Get(ParamAllNamespaces).AsBool(),
	)

	return m.containersPublisher.PublishContainers(true, []*containercollection.Container{}, containerSelector)
}

func (m *KubeManagerInstance) Stop(gadgetCtx operators.GadgetContext) error {
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
