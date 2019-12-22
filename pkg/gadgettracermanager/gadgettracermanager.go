package gadgettracermanager

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"time"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	_ "github.com/iovisor/gobpf/pkg/bpffs"
	_ "github.com/iovisor/gobpf/pkg/cpuonline"

	"google.golang.org/grpc"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

type GadgetTracerManager struct {
	// mux protects the two maps: containers and tracers
	mux sync.Mutex

	// containers by ContainerId
	containers map[string]pb.ContainerDefinition

	// tracers by tracerId
	tracers map[string]tracer
}

type tracer struct {
	tracerId string

	containerSelector pb.ContainerSelector

	mapHolder          *bpflib.Module
	cgroupIdSetMap     *bpflib.Map
	cgroupIdSetMapPath string

	conn   *grpc.ClientConn
	client pb.TracerClient

	matchesCache []uint64
}

func containerSelectorMatches(s *pb.ContainerSelector, c *pb.ContainerDefinition) bool {
	if s.Namespace != "" && s.Namespace != c.Namespace {
		return false
	}
	if s.Podname != "" && s.Podname != c.Podname {
		return false
	}
	if s.ContainerIndex != -1 && s.ContainerIndex != c.ContainerIndex {
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

	buf, err := Asset("tracer-map.o")
	if err != nil {
		return nil, fmt.Errorf("couldn't find asset: %s", err)
	}
	reader := bytes.NewReader(buf)

	m := bpflib.NewModuleFromReader(reader)
	if m == nil {
		return nil, fmt.Errorf("BPF not supported")
	}

	cgroupIdSetMapPath := fmt.Sprintf("gadget/cgroupidset-%s", tracerId)
	var sectionParams = map[string]bpflib.SectionParams{
		"maps/cgroupid_set": bpflib.SectionParams{
			PinPath: cgroupIdSetMapPath,
		},
	}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}
	cgroupIdSetMap := m.Map("cgroupid_set")

	matchesCache := []uint64{}

	g.mux.Lock()
	defer g.mux.Unlock()

	for _, c := range g.containers {
		if containerSelectorMatches(req.Selector, &c) {
			matchesCache = append(matchesCache, c.CgroupId)
			cgroupIdC := uint64(c.CgroupId)
			zero := uint32(0)
			m.UpdateElement(cgroupIdSetMap, unsafe.Pointer(&cgroupIdC), unsafe.Pointer(&zero), 0)
		}
	}

	g.tracers[tracerId] = tracer{
		tracerId:           tracerId,
		containerSelector:  *req.Selector,
		mapHolder:          m,
		cgroupIdSetMap:     cgroupIdSetMap,
		cgroupIdSetMapPath: cgroupIdSetMapPath,
		matchesCache:       matchesCache,
	}

	return &pb.TracerID{Id: tracerId}, nil
}

func (g *GadgetTracerManager) RemoveTracer(ctx context.Context, tracerID *pb.TracerID) (*pb.RemoveTracerResponse, error) {
	if tracerID.Id == "" {
		return nil, fmt.Errorf("cannot remove tracer: Id not set")
	}

	g.mux.Lock()
	defer g.mux.Unlock()

	t, ok := g.tracers[tracerID.Id]
	if !ok {
		return nil, fmt.Errorf("cannot remove tracer: unknown tracer %q", tracerID.Id)
	}

	t.mapHolder.Close()
	os.Remove("/sys/fs/bpf/" + t.cgroupIdSetMapPath)
	if t.conn != nil {
		t.conn.Close()
	}

	delete(g.tracers, tracerID.Id)

	return &pb.RemoveTracerResponse{}, nil
}

func (g *GadgetTracerManager) TracerSubscribeContainers(req *pb.TracerSubscribeContainersRequest, stream pb.GadgetTracerManager_TracerSubscribeContainersServer) error {
	if req.TracerId == "" {
		return fmt.Errorf("cannot subscribe to container events for tracer: Id not set")
	}
	if req.SocketFile == "" {
		return fmt.Errorf("cannot subscribe to container events for tracer: socket file not set")
	}

	g.mux.Lock()
	defer g.mux.Unlock()

	t, ok := g.tracers[req.TracerId]
	if !ok {
		return fmt.Errorf("cannot find tracer: unknown tracer %q", req.TracerId)
	}

	// Connect to the tracer
	if t.client != nil {
		return fmt.Errorf("client to tracer %q already exists", req.TracerId)
	}
	var err error
	t.conn, err = grpc.Dial("unix://"+req.SocketFile, grpc.WithInsecure())
	if err != nil {
		return err
	}
	t.client = pb.NewTracerClient(t.conn)

	// Send initial set of container ids
	currentContainerList := []*pb.ContainerDefinition{}
	for _, c := range g.containers {
		if containerSelectorMatches(&t.containerSelector, &c) {
			currentContainerList = append(currentContainerList, &c)
		}
	}

	var ctx context.Context
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err = t.client.UpdateContainers(ctx, &pb.UpdateContainersRequest{
		Added:   currentContainerList,
		Removed: nil,
	})
	if err != nil {
		return err
	}

	return nil
}

func (g *GadgetTracerManager) AddContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	if containerDefinition.ContainerId == "" || containerDefinition.CgroupId == 0 {
		return nil, fmt.Errorf("cannot add container: container id or cgroup id not set")
	}

	g.mux.Lock()
	defer g.mux.Unlock()

	if _, ok := g.containers[containerDefinition.ContainerId]; ok {
		return nil, fmt.Errorf("container with cgroup id %v already exists", containerDefinition.CgroupId)
	}

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, containerDefinition) {
			t.matchesCache = append(t.matchesCache, containerDefinition.CgroupId)
			cgroupIdC := uint64(containerDefinition.CgroupId)
			zero := uint32(0)
			t.mapHolder.UpdateElement(t.cgroupIdSetMap, unsafe.Pointer(&cgroupIdC), unsafe.Pointer(&zero), 0)

			if t.client != nil {
				var ctx context.Context
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()
				_, err := t.client.UpdateContainers(ctx, &pb.UpdateContainersRequest{
					Added:   []*pb.ContainerDefinition{containerDefinition},
					Removed: nil,
				})
				if err != nil {
					fmt.Printf("Cannot add container %q to tracer %q: %s\n", containerDefinition.ContainerId, t.tracerId, err)
				}
			}
		}
	}

	g.containers[containerDefinition.ContainerId] = *containerDefinition

	return &pb.AddContainerResponse{}, nil
}

func (g *GadgetTracerManager) RemoveContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.RemoveContainerResponse, error) {
	if containerDefinition.ContainerId == "" {
		return nil, fmt.Errorf("cannot remove container: ContainerId not set")
	}

	g.mux.Lock()
	defer g.mux.Unlock()

	c, ok := g.containers[containerDefinition.ContainerId]
	if !ok {
		return nil, fmt.Errorf("cannot remove container: unknown container %q", containerDefinition.ContainerId)
	}

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, &c) {
			//TODO: t.matchesCache = remove_from(t.matchesCache, c.CgroupId)
			cgroupIdC := uint64(c.CgroupId)
			t.mapHolder.DeleteElement(t.cgroupIdSetMap, unsafe.Pointer(&cgroupIdC))

			if t.client != nil {
				var ctx context.Context
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(context.Background(), 1*time.Second)
				defer cancel()
				_, err := t.client.UpdateContainers(ctx, &pb.UpdateContainersRequest{
					Added:   nil,
					Removed: []*pb.ContainerDefinition{containerDefinition},
				})
				if err != nil {
					fmt.Printf("Cannot remove container %q from tracer %q: %s\n", containerDefinition.ContainerId, t.tracerId, err)
				}
			}

		}
	}

	delete(g.containers, containerDefinition.ContainerId)

	return &pb.RemoveContainerResponse{}, nil
}

func (g *GadgetTracerManager) DumpState(ctx context.Context, req *pb.DumpStateRequest) (*pb.Dump, error) {
	g.mux.Lock()
	defer g.mux.Unlock()

	out := "List of containers:\n"
	for i, c := range g.containers {
		out += fmt.Sprintf("%v -> %+v\n", i, c)
	}
	out += "List of tracers:\n"
	for i, t := range g.tracers {
		out += fmt.Sprintf("%v -> Labels: \n", i)
		for _, l := range t.containerSelector.Labels {
			out += fmt.Sprintf("                  %v: %v\n", l.Key, l.Value)
		}
		out += fmt.Sprintf("                Container index: %v\n", t.containerSelector.ContainerIndex)
		out += fmt.Sprintf("                Matches: %v\n", t.matchesCache)
	}
	return &pb.Dump{State: out}, nil
}

func NewServer() *GadgetTracerManager {
	g := &GadgetTracerManager{
		containers: make(map[string]pb.ContainerDefinition),
		tracers:    make(map[string]tracer),
	}

	return g
}
