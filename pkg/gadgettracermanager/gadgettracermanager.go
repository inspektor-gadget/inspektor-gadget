// Copyright 2019-2021 The Inspektor Gadget authors
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
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	containersmap "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/stream"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

import "C"

type GadgetTracerManager struct {
	pb.UnimplementedGadgetTracerManagerServer
	containercollection.ContainerCollection

	// mu protects the tracers map from concurrent access
	mu sync.Mutex

	// node where this instance is running
	nodeName string

	// tracers by tracerId
	tracers map[string]tracer

	// withBPF tells whether GadgetTracerManager can run bpf() syscall.
	// Normally, withBPF=true but it can be disabled so unit tests can run
	// without being root.
	withBPF bool

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
}

type tracer struct {
	tracerID string

	containerSelector pb.ContainerSelector

	cgroupIDSetMap *ebpf.Map
	mntnsSetMap    *ebpf.Map

	gadgetStream *stream.GadgetStream
}

func (g *GadgetTracerManager) AddTracer(_ context.Context, req *pb.AddTracerRequest) (*pb.TracerID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	tracerID := ""
	if req.Id == "" {
		b := make([]byte, 6)
		_, err := rand.Read(b)
		if err != nil {
			return nil, fmt.Errorf("cannot generate random number: %w", err)
		}
		tracerID = fmt.Sprintf("%x", b)
	} else {
		tracerID = req.Id
	}
	if _, ok := g.tracers[tracerID]; ok {
		return nil, fmt.Errorf("tracer id %q: %w", tracerID, os.ErrExist)
	}

	// Create and pin BPF maps for this tracer.
	var mntnsSetMap, cgroupIDSetMap *ebpf.Map
	var err error
	if g.withBPF {
		cgroupIDSpec := &ebpf.MapSpec{
			Name:       gadgets.CGroupMapPrefix + tracerID,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MaxContainersPerNode,
			Pinning:    ebpf.PinByName,
		}
		cgroupIDSetMap, err = ebpf.NewMapWithOptions(cgroupIDSpec, ebpf.MapOptions{PinPath: gadgets.PinPath})
		if err != nil {
			return nil, fmt.Errorf("error creating cgroupid map: %w", err)
		}

		mntnsSpec := &ebpf.MapSpec{
			Name:       gadgets.MountMapPrefix + tracerID,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MaxContainersPerNode,
			Pinning:    ebpf.PinByName,
		}
		mntnsSetMap, err = ebpf.NewMapWithOptions(mntnsSpec, ebpf.MapOptions{PinPath: gadgets.PinPath})
		if err != nil {
			return nil, fmt.Errorf("error creating mntnsset map: %w", err)
		}

		g.ContainerRangeWithSelector(req.Selector, func(c *pb.ContainerDefinition) {
			one := uint32(1)
			cgroupIDC := uint64(c.CgroupId)
			if cgroupIDC != 0 {
				cgroupIDSetMap.Put(cgroupIDC, one)
			}
			mntnsC := uint64(c.Mntns)
			if mntnsC != 0 {
				mntnsSetMap.Put(mntnsC, one)
			}
		})
	}

	g.tracers[tracerID] = tracer{
		tracerID:          tracerID,
		containerSelector: *req.Selector,
		cgroupIDSetMap:    cgroupIDSetMap,
		mntnsSetMap:       mntnsSetMap,
		gadgetStream:      stream.NewGadgetStream(),
	}
	return &pb.TracerID{Id: tracerID}, nil
}

func (g *GadgetTracerManager) RemoveTracer(_ context.Context, tracerID *pb.TracerID) (*pb.RemoveTracerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if tracerID.Id == "" {
		return nil, fmt.Errorf("cannot remove tracer: Id not set")
	}

	t, ok := g.tracers[tracerID.Id]
	if !ok {
		return nil, fmt.Errorf("cannot remove tracer: unknown tracer %q", tracerID.Id)
	}

	if t.cgroupIDSetMap != nil {
		t.cgroupIDSetMap.Close()
	}
	if t.mntnsSetMap != nil {
		t.mntnsSetMap.Close()
	}

	t.gadgetStream.Close()

	if g.withBPF {
		os.Remove(filepath.Join(gadgets.PinPath, gadgets.CGroupMapPrefix+t.tracerID))
		os.Remove(filepath.Join(gadgets.PinPath, gadgets.MountMapPrefix+t.tracerID))
	}

	delete(g.tracers, tracerID.Id)
	return &pb.RemoveTracerResponse{}, nil
}

func (g *GadgetTracerManager) ReceiveStream(tracerID *pb.TracerID, stream pb.GadgetTracerManager_ReceiveStreamServer) error {
	if tracerID.Id == "" {
		return fmt.Errorf("cannot find tracer: Id not set")
	}

	g.mu.Lock()

	t, ok := g.tracers[tracerID.Id]
	if !ok {
		g.mu.Unlock()
		return fmt.Errorf("cannot find tracer: unknown tracer %q", tracerID.Id)
	}

	ch := t.gadgetStream.Subscribe()
	defer t.gadgetStream.Unsubscribe(ch)

	g.mu.Unlock()

	for l := range ch {
		if l.EventLost {
			msg := fmt.Sprintf(`{"err": "events lost", "node": "%s"}\n`, g.nodeName)
			err := stream.Send(&pb.StreamData{Line: msg})
			return err
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

	t, ok := g.tracers[tracerID]
	if !ok {
		return fmt.Errorf("cannot find tracer: unknown tracer %q", tracerID)
	}

	t.gadgetStream.Publish(line)
	return nil
}

func (g *GadgetTracerManager) AddContainer(_ context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("cannot add container: container id not set")
	}
	if g.ContainerCollection.GetContainer(containerDefinition.Id) != nil {
		return nil, fmt.Errorf("container with id %s already exists", containerDefinition.Id)
	}

	g.ContainerCollection.AddContainer(containerDefinition)

	return &pb.AddContainerResponse{}, nil
}

func (g *GadgetTracerManager) RemoveContainer(_ context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("cannot remove container: Id not set")
	}

	c := g.ContainerCollection.GetContainer(containerDefinition.Id)
	if c == nil {
		return nil, fmt.Errorf("cannot remove container: unknown container %q", containerDefinition.Id)
	}

	g.ContainerCollection.RemoveContainer(containerDefinition.Id)
	return &pb.RemoveContainerResponse{}, nil
}

func (g *GadgetTracerManager) DumpState(_ context.Context, req *pb.DumpStateRequest) (*pb.Dump, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := "List of containers:\n"
	g.ContainerRange(func(c *pb.ContainerDefinition) {
		out += fmt.Sprintf("%+v\n", c)
	})
	out += "List of tracers:\n"
	for i, t := range g.tracers {
		out += fmt.Sprintf("%v -> %q/%q (%s) Labels: \n",
			i,
			t.containerSelector.Namespace,
			t.containerSelector.Podname,
			t.containerSelector.Name)
		for _, l := range t.containerSelector.Labels {
			out += fmt.Sprintf("                  %v: %v\n", l.Key, l.Value)
		}
		out += "        Matches:\n"
		g.ContainerRangeWithSelector(&t.containerSelector, func(c *pb.ContainerDefinition) {
			out += fmt.Sprintf("        - %s/%s [Mntns=%v CgroupId=%v]\n", c.Namespace, c.Podname, c.Mntns, c.CgroupId)
		})
	}
	out += "List of stacks:\n"
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	out += fmt.Sprintf("%s\n", buf[:stacklen])

	return &pb.Dump{State: out}, nil
}

func newServer(conf *Conf) (*GadgetTracerManager, error) {
	g := &GadgetTracerManager{
		nodeName: conf.NodeName,
		tracers:  make(map[string]tracer),
		withBPF:  !conf.TestOnly,
	}

	containerEventFuncs := []pubsub.FuncNotify{}

	if !conf.TestOnly {
		if _, err := ebpf.RemoveMemlockRlimit(); err != nil {
			return nil, err
		}

		var err error
		if g.containersMap, err = containersmap.NewContainersMap(gadgets.PinPath); err != nil {
			return nil, fmt.Errorf("error creating containers map: %w", err)
		}

		containerEventFuncs = append(containerEventFuncs, g.containersMap.ContainersMapUpdater())

		containerEventFuncs = append(containerEventFuncs, func(event pubsub.PubSubEvent) {
			switch event.Type {
			case pubsub.EventTypeAddContainer:
				// Skip the pause container
				if event.Container.Name == "" {
					return
				}

				log.Infof("pubsub: ADD_CONTAINER: %s/%s/%s", event.Container.Namespace, event.Container.Podname, event.Container.Name)

				for _, t := range g.tracers {
					if containercollection.ContainerSelectorMatches(&t.containerSelector, &event.Container) {
						cgroupIDC := uint64(event.Container.CgroupId)
						mntnsC := uint64(event.Container.Mntns)
						one := uint32(1)
						if cgroupIDC != 0 {
							t.cgroupIDSetMap.Put(cgroupIDC, one)
						}
						if mntnsC != 0 {
							t.mntnsSetMap.Put(mntnsC, one)
						} else {
							log.Errorf("new container with mntns=0")
						}
					}
				}

			case pubsub.EventTypeRemoveContainer:
				log.Infof("pubsub: REMOVE_CONTAINER: %s/%s/%s", event.Container.Namespace, event.Container.Podname, event.Container.Name)

				for _, t := range g.tracers {
					if containercollection.ContainerSelectorMatches(&t.containerSelector, &event.Container) {
						cgroupIDC := uint64(event.Container.CgroupId)
						mntnsC := uint64(event.Container.Mntns)
						t.cgroupIDSetMap.Delete(cgroupIDC)
						t.mntnsSetMap.Delete(mntnsC)
					}
				}
			}
		})
	}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(containerEventFuncs...),
	}
	if !conf.TestOnly {
		opts = append(opts, containercollection.WithCgroupEnrichment())
		opts = append(opts, containercollection.WithLinuxNamespaceEnrichment())
		opts = append(opts, containercollection.WithKubernetesEnrichment(g.nodeName))
	}

	switch conf.HookMode {
	case "none":
		// Nothing to do: grpc calls will be enough
		// Used by nri and crio
		log.Infof("GadgetTracerManager: hook mode: none")
		if !conf.TestOnly {
			opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
		}
	case "auto":
		if runcfanotify.Supported() {
			log.Infof("GadgetTracerManager: hook mode: fanotify (auto)")
			opts = append(opts, containercollection.WithRuncFanotify())
			opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
		} else {
			log.Infof("GadgetTracerManager: hook mode: podinformer (auto)")
			opts = append(opts, containercollection.WithPodInformer(g.nodeName))
		}
	case "podinformer":
		log.Infof("GadgetTracerManager: hook mode: podinformer")
		opts = append(opts, containercollection.WithPodInformer(g.nodeName))
	case "fanotify":
		log.Infof("GadgetTracerManager: hook mode: fanotify")
		opts = append(opts, containercollection.WithRuncFanotify())
		opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
	default:
		return nil, fmt.Errorf("invalid hook mode: %s", conf.HookMode)
	}

	if conf.FallbackPodInformer && conf.HookMode != "podinformer" {
		log.Infof("GadgetTracerManager: enabling fallback podinformer")
		opts = append(opts, containercollection.WithFallbackPodInformer(g.nodeName))
	}

	err := g.ContainerCollectionInitialize(opts...)
	if err != nil {
		return nil, err
	}

	return g, nil
}

type Conf struct {
	NodeName            string
	HookMode            string
	FallbackPodInformer bool
	TestOnly            bool
}

func NewServer(conf *Conf) (*GadgetTracerManager, error) {
	return newServer(conf)
}

// Close releases any resource that could be in use by the tracer manager, like
// ebpf maps.
func (m *GadgetTracerManager) Close() {
	m.containersMap.Close()
}
