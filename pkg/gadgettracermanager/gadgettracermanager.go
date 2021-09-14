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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"unsafe"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
	v1 "k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/k8s"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/pubsub"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/stream"
	"github.com/kinvolk/inspektor-gadget/pkg/runcfanotify"
)

import "C"

type GadgetTracerManager struct {
	pb.UnimplementedGadgetTracerManagerServer

	// mu protects the containers and tracers maps from concurrent access
	mu sync.Mutex

	// node where this instance is running
	nodeName string

	// client to talk to the k8s API server to get information about pods
	k8sClient *k8s.K8sClient

	// containers by Id
	containers map[string]pb.ContainerDefinition

	// tracers by tracerId
	tracers map[string]tracer

	podInformer *k8s.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string

	runcNotifier *runcfanotify.RuncNotifier

	// withBPF tells whether GadgetTracerManager can run bpf() syscall.
	// Normally, withBPF=true but it can be disabled so unit tests can run
	// without being root.
	withBPF bool

	// containersMap is the global map at /sys/fs/bpf/gadget/containers
	// exposing container details for each mount namespace.
	containersMap *ebpf.Map

	// subs contains a list of subscribers
	pubsub *pubsub.GadgetPubSub
}

type tracer struct {
	tracerId string

	containerSelector pb.ContainerSelector

	cgroupIdSetMap *ebpf.Map
	mntnsSetMap    *ebpf.Map

	gadgetStream *stream.GadgetStream
}

func containerSelectorMatches(s *pb.ContainerSelector, c *pb.ContainerDefinition) bool {
	if s.Namespace != "" && s.Namespace != c.Namespace {
		return false
	}
	if s.Podname != "" && s.Podname != c.Podname {
		return false
	}
	if s.Name != "" && s.Name != c.Name {
		return false
	}
	for _, l := range s.Labels {
		found := false
		for _, cl := range c.Labels {
			if cl.Key == l.Key && cl.Value == l.Value {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

func (g *GadgetTracerManager) AddTracer(ctx context.Context, req *pb.AddTracerRequest) (*pb.TracerID, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	tracerId := ""
	if req.Id == "" {
		b := make([]byte, 6)
		_, err := rand.Read(b)
		if err != nil {
			return nil, fmt.Errorf("cannot generate random number: %v", err)
		}
		tracerId = fmt.Sprintf("%x", b)
	} else {
		tracerId = req.Id
	}
	if _, ok := g.tracers[tracerId]; ok {
		return nil, fmt.Errorf("tracer id %q: %w", tracerId, os.ErrExist)
	}

	// Create and pin BPF maps for this tracer.
	var mntnsSetMap, cgroupIdSetMap *ebpf.Map
	var err error
	if g.withBPF {
		cgroupIdSpec := &ebpf.MapSpec{
			Name:       gadgets.CGROUPMAP_PREFIX + tracerId,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MAX_CONTAINERS_PER_NODE,
			Pinning:    ebpf.PinByName,
		}
		cgroupIdSetMap, err = ebpf.NewMapWithOptions(cgroupIdSpec, ebpf.MapOptions{PinPath: gadgets.PIN_PATH})
		if err != nil {
			return nil, fmt.Errorf("error creating cgroupid map: %w", err)
		}

		mntnsSpec := &ebpf.MapSpec{
			Name:       gadgets.MNTMAP_PREFIX + tracerId,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  4,
			MaxEntries: MAX_CONTAINERS_PER_NODE,
			Pinning:    ebpf.PinByName,
		}
		mntnsSetMap, err = ebpf.NewMapWithOptions(mntnsSpec, ebpf.MapOptions{PinPath: gadgets.PIN_PATH})
		if err != nil {
			return nil, fmt.Errorf("error creating mntnsset map: %w", err)
		}

		for _, c := range g.containers {
			if containerSelectorMatches(req.Selector, &c) {
				one := uint32(1)
				cgroupIdC := uint64(c.CgroupId)
				if cgroupIdC != 0 {
					cgroupIdSetMap.Put(cgroupIdC, one)
				}
				mntnsC := uint64(c.Mntns)
				if mntnsC != 0 {
					mntnsSetMap.Put(mntnsC, one)
				}
			}
		}
	}

	g.tracers[tracerId] = tracer{
		tracerId:          tracerId,
		containerSelector: *req.Selector,
		cgroupIdSetMap:    cgroupIdSetMap,
		mntnsSetMap:       mntnsSetMap,
		gadgetStream:      stream.NewGadgetStream(),
	}
	return &pb.TracerID{Id: tracerId}, nil
}

func (g *GadgetTracerManager) RemoveTracer(ctx context.Context, tracerID *pb.TracerID) (*pb.RemoveTracerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if tracerID.Id == "" {
		return nil, fmt.Errorf("cannot remove tracer: Id not set")
	}

	t, ok := g.tracers[tracerID.Id]
	if !ok {
		return nil, fmt.Errorf("cannot remove tracer: unknown tracer %q", tracerID.Id)
	}

	if t.cgroupIdSetMap != nil {
		t.cgroupIdSetMap.Close()
	}
	if t.mntnsSetMap != nil {
		t.mntnsSetMap.Close()
	}

	t.gadgetStream.Close()

	if g.withBPF {
		os.Remove(filepath.Join(gadgets.PIN_PATH, gadgets.CGROUPMAP_PREFIX+t.tracerId))
		os.Remove(filepath.Join(gadgets.PIN_PATH, gadgets.MNTMAP_PREFIX+t.tracerId))
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
	//g.mu.Lock()
	//defer g.mu.Unlock()

	t, ok := g.tracers[tracerID]
	if !ok {
		return fmt.Errorf("cannot find tracer: unknown tracer %q", tracerID)
	}

	t.gadgetStream.Publish(line)
	return nil
}

func (g *GadgetTracerManager) AddContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("cannot add container: container id not set")
	}
	if _, ok := g.containers[containerDefinition.Id]; ok {
		return nil, fmt.Errorf("container with id %s already exists", containerDefinition.Id)
	}

	// If the pod name isn't provided, use k8s API server to get the
	// missing information about the container.
	if containerDefinition.Podname == "" {
		if g.k8sClient == nil {
			return nil, fmt.Errorf("container with id %s does not have a pod name and access to the Kubernetes API is disabled", containerDefinition.Id)
		}
		if err := g.k8sClient.FillContainer(containerDefinition); err != nil {
			return nil, err
		}
		if containerDefinition.Podname == "" {
			return nil, fmt.Errorf("container with id %s not found in Kubernetes", containerDefinition.Id)
		}
		// Skip the pause container
		if containerDefinition.Name == "" {
			return nil, fmt.Errorf("container with id %s is the pause container and cannot be added", containerDefinition.Id)
		}
	}

	if g.withBPF {
		for _, t := range g.tracers {
			if containerSelectorMatches(&t.containerSelector, containerDefinition) {
				cgroupIdC := uint64(containerDefinition.CgroupId)
				mntnsC := uint64(containerDefinition.Mntns)
				one := uint32(1)
				if cgroupIdC != 0 {
					t.cgroupIdSetMap.Put(cgroupIdC, one)
				}
				if mntnsC != 0 {
					t.mntnsSetMap.Put(mntnsC, one)
				}
			}
		}
	}

	g.containers[containerDefinition.Id] = *containerDefinition
	g.addContainerInMap(*containerDefinition)
	g.pubsub.Publish(pubsub.EVENT_TYPE_ADD_CONTAINER, *containerDefinition)
	return &pb.AddContainerResponse{}, nil
}

func (g *GadgetTracerManager) RemoveContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if containerDefinition.Id == "" {
		return nil, fmt.Errorf("cannot remove container: Id not set")
	}

	c, ok := g.containers[containerDefinition.Id]
	if !ok {
		return nil, fmt.Errorf("cannot remove container: unknown container %q", containerDefinition.Id)
	}

	g.pubsub.Publish(pubsub.EVENT_TYPE_REMOVE_CONTAINER, c)

	if g.withBPF {
		for _, t := range g.tracers {
			if containerSelectorMatches(&t.containerSelector, &c) {
				cgroupIdC := uint64(c.CgroupId)
				mntnsC := uint64(c.Mntns)
				t.cgroupIdSetMap.Delete(cgroupIdC)
				t.mntnsSetMap.Delete(mntnsC)
			}
		}
	}

	g.deleteContainerFromMap(c)
	delete(g.containers, containerDefinition.Id)
	return &pb.RemoveContainerResponse{}, nil
}

// LookupMntnsByContainer returns the mount namespace inode of the container
// specified in arguments or zero if not found
func (g *GadgetTracerManager) LookupMntnsByContainer(namespace, pod, container string) uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, c := range g.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		if container != c.Name {
			continue
		}
		return c.Mntns
	}
	return 0
}

// LookupMntnsByPod returns the mount namespace inodes of all containers
// belonging to the pod specified in arguments, indexed by the name of the
// containers or an empty map if not found
func (g *GadgetTracerManager) LookupMntnsByPod(namespace, pod string) map[string]uint64 {
	g.mu.Lock()
	defer g.mu.Unlock()

	ret := make(map[string]uint64)
	for _, c := range g.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		ret[c.Name] = c.Mntns
	}
	return ret
}

// LookupPIDByContainer returns the PID of the container
// specified in arguments or zero if not found
func (g *GadgetTracerManager) LookupPIDByContainer(namespace, pod, container string) uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()

	for _, c := range g.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		if container != c.Name {
			continue
		}
		return c.Pid
	}
	return 0
}

// LookupPIDByPod returns the PID of all containers belonging to
// the pod specified in arguments, indexed by the name of the
// containers or an empty map if not found
func (g *GadgetTracerManager) LookupPIDByPod(namespace, pod string) map[string]uint32 {
	g.mu.Lock()
	defer g.mu.Unlock()

	ret := make(map[string]uint32)
	for _, c := range g.containers {
		if namespace != c.Namespace {
			continue
		}
		if pod != c.Podname {
			continue
		}
		ret[c.Name] = c.Pid
	}
	return ret
}

// GetContainersBySelector returns a slice of containers that match
// the selector or an empty slice if there are not matches
func (g *GadgetTracerManager) GetContainersBySelector(containerSelector *pb.ContainerSelector) []pb.ContainerDefinition {
	g.mu.Lock()
	defer g.mu.Unlock()

	selectedContainers := []pb.ContainerDefinition{}
	for _, c := range g.containers {
		if containerSelectorMatches(containerSelector, &c) {
			selectedContainers = append(selectedContainers, c)
		}
	}
	return selectedContainers
}

func (g *GadgetTracerManager) DumpState(ctx context.Context, req *pb.DumpStateRequest) (*pb.Dump, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	out := "List of containers:\n"
	for i, c := range g.containers {
		out += fmt.Sprintf("%v -> %+v\n", i, c)
	}
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
		out += fmt.Sprintf("        Matches:\n")
		for _, c := range g.containers {
			if containerSelectorMatches(&t.containerSelector, &c) {
				out += fmt.Sprintf("        - %s/%s [Mntns=%v CgroupId=%v]\n", c.Namespace, c.Podname, c.Mntns, c.CgroupId)
			}
		}
	}
	return &pb.Dump{State: out}, nil
}

func (g *GadgetTracerManager) run() {
	// containerIDsByKey keeps track of container ids for each key. This is
	// necessary because messages from deletedChan only gives the key
	// without additional context.
	//
	// key is "namespace/podname"
	// value is an set of containerId
	containerIDsByKey := make(map[string]map[string]struct{})

	for {
		select {
		case d := <-g.deletedChan:
			if containerIDs, ok := containerIDsByKey[d]; ok {
				for containerID, _ := range containerIDs {
					containerDefinition := &pb.ContainerDefinition{
						Id: containerID,
					}
					g.RemoveContainer(nil, containerDefinition)
				}
			}
		case c := <-g.createdChan:
			containers := g.k8sClient.PodToContainers(c)
			key, _ := cache.MetaNamespaceKeyFunc(c)
			containerIDs, ok := containerIDsByKey[key]
			if !ok {
				containerIDs = make(map[string]struct{})
				containerIDsByKey[key] = containerIDs
			}
			for _, container := range containers {
				// The container is already registered, there is not any chance the
				// PID will change, so ignore it.
				if _, ok := containerIDs[container.Id]; ok {
					continue
				}

				g.AddContainer(nil, &container)
				containerIDs[container.Id] = struct{}{}
			}
		}
	}
}

// createContainersMap creates a global map /sys/fs/bpf/gadget/containers
// exposing container details for each mount namespace.
//
// This makes it possible for gadgets to access that information and
// display it directly from the BPF code. Example of such code:
//
//     struct container *container_entry;
//     container_entry = bpf_map_lookup_elem(&containers, &mntns_id);
//
// See usage in gadget-container/gadgets/.../bpf/*.c
//
// External tools such as tracee or bpftrace could also benefit from this just
// by using this "containers" map (other interaction with Inspektor Gadget is
// not necessary for this).
func (g *GadgetTracerManager) createContainersMap() error {
	// Create and pin BPF map
	containersMapSpec := &ebpf.MapSpec{
		Name:       "containers",
		Type:       ebpf.Hash,
		KeySize:    8,
		ValueSize:  uint32(unsafe.Sizeof(container{})),
		MaxEntries: MAX_CONTAINERS_PER_NODE,
		Pinning:    ebpf.PinByName,
	}
	var err error
	log.Printf("Creating BPF map: %s/%s", gadgets.PIN_PATH, containersMapSpec.Name)
	g.containersMap, err = ebpf.NewMapWithOptions(containersMapSpec,
		ebpf.MapOptions{PinPath: gadgets.PIN_PATH})
	if err != nil {
		return fmt.Errorf("error creating containers map: %w", err)
	}
	return nil
}

func (g *GadgetTracerManager) addContainerInMap(c pb.ContainerDefinition) {
	if g.containersMap == nil || c.Mntns == 0 {
		return
	}
	mntnsC := uint64(c.Mntns)

	val := container{}

	copyToC(&val.container_id, c.Id)
	copyToC(&val.kubernetes_namespace, c.Namespace)
	copyToC(&val.kubernetes_pod, c.Podname)
	copyToC(&val.kubernetes_container, c.Name)

	g.containersMap.Put(mntnsC, val)
}

func (g *GadgetTracerManager) deleteContainerFromMap(c pb.ContainerDefinition) {
	if g.containersMap == nil || c.Mntns == 0 {
		return
	}
	g.containersMap.Delete(uint64(c.Mntns))
}

// Subscribe returns the list of existing containers and registers a callback
// for notifications about additions and deletions of containers
func (g *GadgetTracerManager) Subscribe(key interface{}, selector pb.ContainerSelector, f pubsub.FuncNotify) []pb.ContainerDefinition {
	g.mu.Lock()
	defer g.mu.Unlock()

	g.pubsub.Subscribe(key, func(event pubsub.PubSubEvent) {
		if containerSelectorMatches(&selector, &event.Container) {
			f(event)
		}
	})
	ret := []pb.ContainerDefinition{}
	for _, c := range g.containers {
		if containerSelectorMatches(&selector, &c) {
			ret = append(ret, c)
		}
	}
	return ret
}

// Unsubscribe undoes a previous call to Subscribe
func (g *GadgetTracerManager) Unsubscribe(key interface{}) {
	g.pubsub.Unsubscribe(key)
}

func newServer(nodeName string, withPodInformer, withRuncFanotify, withBPF, withK8sClient bool) (*GadgetTracerManager, error) {
	g := &GadgetTracerManager{
		nodeName:   nodeName,
		containers: make(map[string]pb.ContainerDefinition),
		tracers:    make(map[string]tracer),
		withBPF:    withBPF,
		pubsub:     pubsub.NewGadgetPubSub(),
	}

	if withBPF {
		if err := initServer(); err != nil {
			return nil, err
		}
	}

	if withK8sClient {
		k8sClient, err := k8s.NewK8sClient(nodeName)
		if err != nil {
			return nil, fmt.Errorf("failed to create k8s client: %w", err)
		}
		g.k8sClient = k8sClient

		if !withPodInformer {
			// The CRI client is only used at the beginning to get the initial list
			// of containers, it's not used after it.
			defer k8sClient.CloseCRI()
		}
	}

	if withPodInformer {
		g.createdChan = make(chan *v1.Pod)
		g.deletedChan = make(chan string)

		podInformer, err := k8s.NewPodInformer(nodeName, g.createdChan, g.deletedChan)
		if err != nil {
			return nil, fmt.Errorf("failed to create pod informer: %w", err)
		}
		g.podInformer = podInformer
	}

	if withRuncFanotify {
		log.Printf("experimental hook mode fanotify")
		runcNotifier, err := runcfanotify.NewRuncNotifier(func(notif runcfanotify.ContainerEvent) {
			switch notif.Type {
			case runcfanotify.EVENT_TYPE_ADD_CONTAINER:
				mountSources := []string{}
				for _, m := range notif.ContainerConfig.Mounts {
					mountSources = append(mountSources, m.Source)
				}
				g.AddContainer(nil, &pb.ContainerDefinition{
					Id:           notif.ContainerID,
					Pid:          notif.ContainerPID,
					MountSources: mountSources,
				})
			case runcfanotify.EVENT_TYPE_REMOVE_CONTAINER:
				g.RemoveContainer(nil, &pb.ContainerDefinition{
					Id: notif.ContainerID,
				})
			}
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create runc fanotifier: %w", err)
		}
		g.runcNotifier = runcNotifier
	}

	if withBPF {
		if err := g.createContainersMap(); err != nil {
			return nil, err
		}
	}

	if withPodInformer {
		go g.run()
	} else if withK8sClient {
		containers, err := g.k8sClient.ListContainers()
		if err != nil {
			log.Printf("gadgettracermanager failed to list containers: %v", err)
		} else {
			log.Printf("gadgettracermanager found %d containers: %+v", len(containers), containers)
			for _, container := range containers {
				g.containers[container.Id] = container
				g.addContainerInMap(container)
			}
		}
	}

	return g, nil
}

func NewServerWithPodInformer(nodeName string) (*GadgetTracerManager, error) {
	return newServer(nodeName, true, false, true, true)
}

func NewServerWithRuncFanotify(nodeName string) (*GadgetTracerManager, error) {
	return newServer(nodeName, false, true, true, true)
}

func NewServer(nodeName string) (*GadgetTracerManager, error) {
	return newServer(nodeName, false, false, true, true)
}

// Close releases any resource that could be in use by the tracer manager, like
// ebpf maps.
func (m *GadgetTracerManager) Close() {
	if m.containersMap != nil {
		os.Remove(filepath.Join(gadgets.PIN_PATH, "containers"))
	}
}

func increaseRlimit() error {
	limit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit)
}

func initServer() error {
	if err := increaseRlimit(); err != nil {
		return fmt.Errorf("failed to increase memlock limit: %w", err)
	}

	if err := os.Mkdir(gadgets.PIN_PATH, 0700); err != nil && !errors.Is(err, unix.EEXIST) {
		return fmt.Errorf("failed to create folder for pinning bpf maps: %w", err)
	}

	return nil
}
