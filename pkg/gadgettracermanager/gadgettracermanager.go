// Copyright 2019-2023 The Inspektor Gadget authors
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

package gadgettracermanager

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	ocispec "github.com/opencontainers/runtime-spec/specs-go"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerhook "github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	pb "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/api"
	containersmap "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	tracercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/tracer-collection"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

type GadgetTracerManager struct {
	pb.UnimplementedGadgetTracerManagerServer
	containercollection.ContainerCollection

	// mu protects the tracers map from concurrent access
	mu sync.Mutex

	// node where this instance is running
	nodeName string

	// tracers
	tracerCollection *tracercollection.TracerCollection

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
}

func (g *GadgetTracerManager) AddTracer(tracerID string, containerSelector containercollection.ContainerSelector) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.tracerCollection.AddTracer(tracerID, containerSelector)
}

func (g *GadgetTracerManager) RemoveTracer(tracerID string) error {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.tracerCollection.RemoveTracer(tracerID)
}

func (g *GadgetTracerManager) ReceiveStream(tracerID *pb.TracerID, stream pb.GadgetTracerManager_ReceiveStreamServer) error {
	if tracerID.Id == "" {
		return fmt.Errorf("tracer Id not set")
	}

	g.mu.Lock()

	gadgetStream, err := g.tracerCollection.Stream(tracerID.Id)
	if err != nil {
		g.mu.Unlock()
		return fmt.Errorf("stream for tracer %q not found", tracerID.Id)
	}

	ch := gadgetStream.Subscribe()
	defer gadgetStream.Unsubscribe(ch)

	g.mu.Unlock()

	if ch == nil {
		return errors.New("tracer was removed before we could subscribe to its stream")
	}

	for l := range ch {
		if l.EventLost {
			ev := eventtypes.Event{
				Type: eventtypes.ERR,
				CommonData: eventtypes.CommonData{
					K8s: eventtypes.K8sMetadata{
						Node: g.nodeName,
					},
				},
				Message: "events lost in gadget tracer manager",
			}
			line, _ := json.Marshal(ev)
			err := stream.Send(&pb.StreamData{Line: string(line)})
			if err != nil {
				return err
			}

			continue
		}

		line := &pb.StreamData{Line: l.Line}
		if err := stream.Send(line); err != nil {
			return err
		}
	}

	return nil
}

func (g *GadgetTracerManager) PublishEvent(tracerID string, line string) error {
	// TODO: reentrant locking :/
	// g.mu.Lock()
	// defer g.mu.Unlock()

	stream, err := g.tracerCollection.Stream(tracerID)
	if err != nil {
		return fmt.Errorf("stream for tracer %q not found", tracerID)
	}

	stream.Publish(line)
	return nil
}

func (g *GadgetTracerManager) TracerMountNsMap(tracerID string) (*ebpf.Map, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	return g.tracerCollection.TracerMountNsMap(tracerID)
}

func (g *GadgetTracerManager) ContainersMap() *ebpf.Map {
	if g.containersMap == nil {
		return nil
	}

	return g.containersMap.ContainersMap()
}

func (g *GadgetTracerManager) AddContainer(_ context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("container id not set")
	}
	if g.GetContainer(containerDefinition.Id) != nil {
		return nil, fmt.Errorf("container with id %s already exists", containerDefinition.Id)
	}

	container := containercollection.Container{
		Runtime: containercollection.RuntimeMetadata{
			BasicRuntimeMetadata: eventtypes.BasicRuntimeMetadata{
				ContainerID:  containerDefinition.Id,
				ContainerPID: containerDefinition.Pid,
			},
		},
		K8s: containercollection.K8sMetadata{
			BasicK8sMetadata: eventtypes.BasicK8sMetadata{
				Namespace:     containerDefinition.Namespace,
				PodName:       containerDefinition.Podname,
				ContainerName: containerDefinition.Name,
			},
		},
	}
	if containerDefinition.LabelsSet {
		container.K8s.PodLabels = make(map[string]string)
		for _, l := range containerDefinition.Labels {
			container.K8s.PodLabels[l.Key] = l.Value
		}
	}
	if containerDefinition.OciConfig != "" {
		containerConfig := &ocispec.Spec{}
		err := json.Unmarshal([]byte(containerDefinition.OciConfig), containerConfig)
		if err != nil {
			return nil, fmt.Errorf("unmarshaling container config: %w", err)
		}
		container.OciConfig = containerConfig
	}

	g.ContainerCollection.AddContainer(&container)

	return &pb.AddContainerResponse{}, nil
}

func (g *GadgetTracerManager) RemoveContainer(_ context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("container Id not set")
	}

	c := g.GetContainer(containerDefinition.Id)
	if c == nil {
		return nil, fmt.Errorf("unknown container %q", containerDefinition.Id)
	}

	g.ContainerCollection.RemoveContainer(containerDefinition.Id)
	return &pb.RemoveContainerResponse{}, nil
}

func (g *GadgetTracerManager) DumpState(_ context.Context, req *pb.DumpStateRequest) (*pb.Dump, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	containers := "List of containers:\n"
	g.ContainerRange(func(c *containercollection.Container) {
		containers += fmt.Sprintf("%+v\n", c)
	})

	traces := "List of tracers:\n"
	traces += g.tracerCollection.TracerDump()

	stacks := "List of stacks:\n"
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	stacks += fmt.Sprintf("%s\n", buf[:stacklen])

	return &pb.Dump{Containers: containers, Traces: traces, Stacks: stacks}, nil
}

func NewServer(conf *Conf) (*GadgetTracerManager, error) {
	g := &GadgetTracerManager{
		nodeName: conf.NodeName,
	}

	eventtypes.Init(conf.NodeName)
	var err error
	if conf.TestOnly {
		g.tracerCollection, err = tracercollection.NewTracerCollectionTest(&g.ContainerCollection)
	} else {
		g.tracerCollection, err = tracercollection.NewTracerCollection(&g.ContainerCollection)
	}
	if err != nil {
		return nil, err
	}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithNodeName(conf.NodeName),
	}

	if !conf.TestOnly {
		if err := rlimit.RemoveMemlock(); err != nil {
			return nil, err
		}

		var err error
		if g.containersMap, err = containersmap.NewContainersMap(gadgets.PinPath); err != nil {
			return nil, fmt.Errorf("creating containers map: %w", err)
		}

		opts = append(opts, containercollection.WithPubSub(g.containersMap.ContainersMapUpdater()))
		opts = append(opts, containercollection.WithOCIConfigEnrichment())
		opts = append(opts, containercollection.WithCgroupEnrichment())
		opts = append(opts, containercollection.WithLinuxNamespaceEnrichment())
		opts = append(opts, containercollection.WithKubernetesEnrichment(g.nodeName, nil))
		opts = append(opts, containercollection.WithTracerCollection(g.tracerCollection))
		opts = append(opts, containercollection.WithProcEnrichment())
	}

	podInformerUsed := false
	switch conf.HookMode {
	case "none":
		// Nothing to do: grpc calls will be enough
		// Used by nri and crio
		log.Infof("GadgetTracerManager: hook mode: none")
		if !conf.TestOnly {
			opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
		}
	case "auto":
		if containerhook.Supported() {
			log.Infof("GadgetTracerManager: hook mode: fanotify+ebpf (auto)")
			opts = append(opts, containercollection.WithContainerFanotifyEbpf())
			opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
		} else {
			log.Infof("GadgetTracerManager: hook mode: podinformer (auto)")
			opts = append(opts, containercollection.WithPodInformer(g.nodeName))
			podInformerUsed = true
		}
	case "podinformer":
		log.Infof("GadgetTracerManager: hook mode: podinformer")
		opts = append(opts, containercollection.WithPodInformer(g.nodeName))
		podInformerUsed = true
	case "fanotify+ebpf":
		log.Infof("GadgetTracerManager: hook mode: fanotify+ebpf")
		opts = append(opts, containercollection.WithContainerFanotifyEbpf())
		opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
	default:
		return nil, fmt.Errorf("invalid hook mode: %s", conf.HookMode)
	}

	if conf.FallbackPodInformer && !podInformerUsed {
		log.Infof("GadgetTracerManager: enabling fallback podinformer")
		opts = append(opts, containercollection.WithFallbackPodInformer(g.nodeName))
	}

	err = g.Initialize(opts...)
	if err != nil {
		return nil, err
	}

	// Dirty hack
	op := operators.GetRaw("KubeManager")
	if setter, ok := op.(SetGadgetTracerMgr); ok {
		setter.SetGadgetTracerMgr(g)
	}
	return g, nil
}

// SetGadgetTracerMgr is an interface that is implemented by KubeManager to be able
// to set a reference to GadgetTracerManager
type SetGadgetTracerMgr interface {
	SetGadgetTracerMgr(*GadgetTracerManager)
}

type Conf struct {
	NodeName            string
	HookMode            string
	FallbackPodInformer bool
	TestOnly            bool
}

// Close releases any resource that could be in use by the tracer manager, like
// ebpf maps.
func (g *GadgetTracerManager) Close() {
	if g.containersMap != nil {
		g.containersMap.Close()
	}
	if g.tracerCollection != nil {
		g.tracerCollection.Close()
	}
	g.ContainerCollection.Close()
}
