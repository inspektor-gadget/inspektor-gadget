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
	"encoding/json"
	"fmt"
	"runtime"
	"sync"

	"github.com/cilium/ebpf/rlimit"
	log "github.com/sirupsen/logrus"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	containersmap "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/containers-map"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
	tracercollection "github.com/kinvolk/inspektor-gadget/pkg/tracer-collection"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

import "C"

type GadgetTracerManager struct {
	pb.UnimplementedGadgetTracerManagerServer
	containercollection.ContainerCollection

	// mu protects the tracers map from concurrent access
	mu sync.Mutex

	// node where this instance is running
	nodeName string

	// tracers
	tracerCollection *tracercollection.TracerCollection

	// withBPF tells whether GadgetTracerManager can run bpf() syscall.
	// Normally, withBPF=true but it can be disabled so unit tests can run
	// without being root.
	withBPF bool

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *containersmap.ContainersMap
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

	if err := g.tracerCollection.AddTracer(tracerID, *req.Selector); err != nil {
		return nil, err
	}

	return &pb.TracerID{Id: tracerID}, nil
}

func (g *GadgetTracerManager) RemoveTracer(_ context.Context, tracerID *pb.TracerID) (*pb.RemoveTracerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := g.tracerCollection.RemoveTracer(tracerID.Id); err != nil {
		return nil, err
	}

	return &pb.RemoveTracerResponse{}, nil
}

func (g *GadgetTracerManager) ReceiveStream(tracerID *pb.TracerID, stream pb.GadgetTracerManager_ReceiveStreamServer) error {
	if tracerID.Id == "" {
		return fmt.Errorf("cannot find tracer: Id not set")
	}

	g.mu.Lock()

	gadgetStream, err := g.tracerCollection.Stream(tracerID.Id)
	if err != nil {
		g.mu.Unlock()
		return fmt.Errorf("cannot find stream for tracer %q", tracerID.Id)
	}

	ch := gadgetStream.Subscribe()
	defer gadgetStream.Unsubscribe(ch)

	g.mu.Unlock()

	for l := range ch {
		if l.EventLost {
			ev := eventtypes.Event{
				Type:    eventtypes.ERR,
				Node:    g.nodeName,
				Message: "events lost in gadget tracer manager",
			}
			line, _ := json.Marshal(ev)
			err := stream.Send(&pb.StreamData{Line: string(line)})
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

	stream, err := g.tracerCollection.Stream(tracerID)
	if err != nil {
		return fmt.Errorf("cannot find stream for tracer %q", tracerID)
	}

	stream.Publish(line)
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
	out += g.tracerCollection.TracerDump()

	out += "List of stacks:\n"
	buf := make([]byte, 1<<20)
	stacklen := runtime.Stack(buf, true)
	out += fmt.Sprintf("%s\n", buf[:stacklen])

	return &pb.Dump{State: out}, nil
}

func newServer(conf *Conf) (*GadgetTracerManager, error) {
	g := &GadgetTracerManager{
		nodeName: conf.NodeName,
		withBPF:  !conf.TestOnly,
	}

	tracerCollection, err := tracercollection.NewTracerCollection(gadgets.PinPath, gadgets.MountMapPrefix, !conf.TestOnly, &g.ContainerCollection)
	if err != nil {
		return nil, err
	}
	g.tracerCollection = tracerCollection

	containerEventFuncs := []pubsub.FuncNotify{}

	if !conf.TestOnly {
		if err := rlimit.RemoveMemlock(); err != nil {
			return nil, err
		}

		var err error
		if g.containersMap, err = containersmap.NewContainersMap(gadgets.PinPath); err != nil {
			return nil, fmt.Errorf("error creating containers map: %w", err)
		}

		containerEventFuncs = append(containerEventFuncs, g.containersMap.ContainersMapUpdater())
		containerEventFuncs = append(containerEventFuncs, g.tracerCollection.TracerMapsUpdater())
	}

	opts := []containercollection.ContainerCollectionOption{
		containercollection.WithPubSub(containerEventFuncs...),
	}
	if !conf.TestOnly {
		opts = append(opts, containercollection.WithCgroupEnrichment())
		opts = append(opts, containercollection.WithLinuxNamespaceEnrichment())
		opts = append(opts, containercollection.WithKubernetesEnrichment(g.nodeName))
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
		if runcfanotify.Supported() {
			log.Infof("GadgetTracerManager: hook mode: fanotify (auto)")
			opts = append(opts, containercollection.WithRuncFanotify())
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
	case "fanotify":
		log.Infof("GadgetTracerManager: hook mode: fanotify")
		opts = append(opts, containercollection.WithRuncFanotify())
		opts = append(opts, containercollection.WithInitialKubernetesContainers(g.nodeName))
	default:
		return nil, fmt.Errorf("invalid hook mode: %s", conf.HookMode)
	}

	if conf.FallbackPodInformer && !podInformerUsed {
		log.Infof("GadgetTracerManager: enabling fallback podinformer")
		opts = append(opts, containercollection.WithFallbackPodInformer(g.nodeName))
	}

	err = g.ContainerCollectionInitialize(opts...)
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
