package gadgettracermanager

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"sync"

	"k8s.io/api/core/v1"
	"k8s.io/client-go/tools/cache"

	bpf "github.com/aquasecurity/tracee/libbpfgo"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/seccomp"
	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/k8s"
)

type GadgetTracerManager struct {
	mu sync.Mutex

	// node where this instance is running
	nodeName string

	// client to talk to the k8s API server to get information about pods
	k8sClient *k8s.K8sClient

	// containers by ContainerId
	containers map[string]pb.ContainerDefinition

	// tracers by tracerId
	tracers map[string]tracer

	podInformer *k8s.PodInformer
	createdChan chan *v1.Pod
	deletedChan chan string
	// containerIDsByKey is a map maintained by the controller
	// key is "namespace/podname"
	// value is an set of containerId
	containerIDsByKey map[string]map[string]struct{}

	seccompAdvisor *seccomp.SeccompAdvisor
}

type tracer struct {
	tracerId string

	containerSelector pb.ContainerSelector

	mapHolder       *bpf.Module
	mntnsSetMap     *bpf.BPFMap
	mntnsSetMapPath string
}

func containerSelectorMatches(s *pb.ContainerSelector, c *pb.ContainerDefinition) bool {
	if s.Namespace != "" && s.Namespace != c.Namespace {
		return false
	}
	if s.Podname != "" && s.Podname != c.Podname {
		return false
	}
	if s.ContainerName != "" && s.ContainerName != c.ContainerName {
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
		return nil, fmt.Errorf("tracer id %q already exists", tracerId)
	}

	buf, err := Asset("maps-bpf-asset.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}

	m, err := bpf.NewModuleFromBuffer(buf, "maps-bpf-asset.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't load BPF module: %s", err)
	}

	mntnsSetMapPath := fmt.Sprintf("gadget/mntnsset-%s", tracerId)
	m.ChangeMapPin("mntns_set", "/sys/fs/bpf/"+mntnsSetMapPath)

	err = m.BPFLoadObject()
	if err != nil {
		return nil, fmt.Errorf("couldn't parse BPF module: %s", err)
	}

	mntnsSetMap, err := m.GetMap("mntns_set")
	if err != nil {
		return nil, err
	}

	for _, c := range g.containers {
		if containerSelectorMatches(req.Selector, &c) {
			one := uint32(1)
			mntnsC := uint64(c.Mntns)
			if mntnsC != 0 {
				mntnsSetMap.Update(mntnsC, one)
			}
		}
	}

	g.tracers[tracerId] = tracer{
		tracerId:          tracerId,
		containerSelector: *req.Selector,
		mapHolder:         m,
		mntnsSetMap:       mntnsSetMap,
		mntnsSetMapPath:   mntnsSetMapPath,
	}

	if tracerId == "seccomp" && g.seccompAdvisor != nil {
		g.seccompAdvisor.Start()
	}

	return &pb.TracerID{Id: tracerId}, nil
}

func (g *GadgetTracerManager) RemoveTracer(ctx context.Context, tracerID *pb.TracerID) (*pb.RemoveTracerResponse, error) {
	if tracerID.Id == "" {
		return nil, fmt.Errorf("cannot remove tracer: Id not set")
	}

	t, ok := g.tracers[tracerID.Id]
	if !ok {
		return nil, fmt.Errorf("cannot remove tracer: unknown tracer %q", tracerID.Id)
	}

	if tracerID.Id == "seccomp" && g.seccompAdvisor != nil {
		g.seccompAdvisor.Stop()
	}

	t.mapHolder.Close()
	os.Remove("/sys/fs/bpf/" + t.mntnsSetMapPath)

	delete(g.tracers, tracerID.Id)
	return &pb.RemoveTracerResponse{}, nil
}

func (g *GadgetTracerManager) QueryTracer(ctx context.Context, tracerID *pb.TracerID) (*pb.QueryTracerResponse, error) {
	if tracerID.Id == "" {
		return nil, fmt.Errorf("cannot query tracer: Id not set")
	}

	_, ok := g.tracers[tracerID.Id]
	if !ok {
		return nil, fmt.Errorf("cannot query tracer: unknown tracer %q", tracerID.Id)
	}

	var out string
	if tracerID.Id == "seccomp" && g.seccompAdvisor != nil {
		out = g.seccompAdvisor.Query()
	}

	return &pb.QueryTracerResponse{Response: out}, nil
}

func (g *GadgetTracerManager) AddContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	if containerDefinition.ContainerId == "" {
		return nil, fmt.Errorf("cannot add container: container id not set")
	}
	if _, ok := g.containers[containerDefinition.ContainerId]; ok {
		return nil, fmt.Errorf("container with id %s already exists", containerDefinition.ContainerId)
	}

	// If the pod name isn't provided, use k8s API server to get the
	// missing information about the container.
	if containerDefinition.Podname == "" {
		if err := g.k8sClient.FillContainer(containerDefinition); err != nil {
			return nil, err
		}
	}

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, containerDefinition) {
			mntnsC := uint64(containerDefinition.Mntns)
			one := uint32(1)
			if mntnsC != 0 {
				t.mntnsSetMap.Update(mntnsC, one)
			}
		}
	}

	g.containers[containerDefinition.ContainerId] = *containerDefinition
	if g.seccompAdvisor != nil {
		g.seccompAdvisor.AddContainer(containerDefinition.Mntns, containerDefinition.Namespace, containerDefinition.Podname, containerDefinition.ContainerName)
	}
	return &pb.AddContainerResponse{}, nil
}

func (g *GadgetTracerManager) RemoveContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	if containerDefinition.ContainerId == "" {
		return nil, fmt.Errorf("cannot remove container: ContainerId not set")
	}

	c, ok := g.containers[containerDefinition.ContainerId]
	if !ok {
		return nil, fmt.Errorf("cannot remove container: unknown container %q", containerDefinition.ContainerId)
	}
	if g.seccompAdvisor != nil {
		g.seccompAdvisor.RemoveContainer(c.Mntns, c.Namespace, c.Podname, c.ContainerName)
	}

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, &c) {
			mntnsC := uint64(c.Mntns)
			t.mntnsSetMap.Delete(mntnsC)
		}
	}

	delete(g.containers, containerDefinition.ContainerId)
	return &pb.RemoveContainerResponse{}, nil
}

func (g *GadgetTracerManager) DumpState(ctx context.Context, req *pb.DumpStateRequest) (*pb.Dump, error) {
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
			t.containerSelector.ContainerName)
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
	if g.seccompAdvisor != nil {
		out += g.seccompAdvisor.Dump()
	}
	return &pb.Dump{State: out}, nil
}

func (g *GadgetTracerManager) run() {
	for {
		select {
		case d := <-g.deletedChan:
			if containerIDs, ok := g.containerIDsByKey[d]; ok {
				for containerID, _ := range containerIDs {
					containerDefinition := &pb.ContainerDefinition{
						ContainerId: containerID,
					}
					g.RemoveContainer(nil, containerDefinition)
				}
			}
		case c := <-g.createdChan:
			containers := g.k8sClient.PodToContainers(c)
			key, _ := cache.MetaNamespaceKeyFunc(c)
			containerIDs, ok := g.containerIDsByKey[key]
			if !ok {
				containerIDs = make(map[string]struct{})
				g.containerIDsByKey[key] = containerIDs
			}
			for _, container := range containers {
				// The container is already registered, there is not any chance the
				// PID will change, so ignore it.
				if _, ok := containerIDs[container.ContainerId]; ok {
					continue
				}

				g.AddContainer(nil, &container)
				containerIDs[container.ContainerId] = struct{}{}
			}
		}
	}
}

func NewServerWithPodInformer(nodeName string) *GadgetTracerManager {
	createdChan := make(chan *v1.Pod)
	deletedChan := make(chan string)

	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil
	}

	podInformer, err := k8s.NewPodInformer(nodeName, createdChan, deletedChan)
	if err != nil {
		return nil
	}

	seccompAdvisor, err := seccomp.NewAdvisor(nodeName)
	if err != nil {
		return nil
	}

	g := &GadgetTracerManager{
		nodeName:          nodeName,
		containers:        make(map[string]pb.ContainerDefinition),
		tracers:           make(map[string]tracer),
		podInformer:       podInformer,
		createdChan:       createdChan,
		deletedChan:       deletedChan,
		containerIDsByKey: make(map[string]map[string]struct{}),
		k8sClient:         k8sClient,
		seccompAdvisor:    seccompAdvisor,
	}

	go g.run()

	return g
}

func NewServer(nodeName string) *GadgetTracerManager {
	k8sClient, err := k8s.NewK8sClient(nodeName)
	if err != nil {
		return nil
	}
	// The CRI client is only used at the beginning to get the initial list
	// of containers, it's not used after it.
	defer k8sClient.CloseCRI()

	g := &GadgetTracerManager{
		nodeName:   nodeName,
		containers: make(map[string]pb.ContainerDefinition),
		tracers:    make(map[string]tracer),
		k8sClient:  k8sClient,
	}

	containers, err := k8sClient.ListContainers()
	if err != nil {
		log.Printf("gadgettracermanager failed to list containers: %v", err)
		for _, container := range containers {
			g.containers[container.ContainerId] = container
		}
	} else {
		log.Printf("gadgettracermanager found %d containers: %+v", len(containers), containers)
	}
	return g
}
