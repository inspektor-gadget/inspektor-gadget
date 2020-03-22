package gadgettracermanager

import (
	"bytes"
	"context"
	"fmt"
	"math/rand"
	"os"
	"sync"
	"unsafe"

	bpflib "github.com/iovisor/gobpf/elf"
	_ "github.com/iovisor/gobpf/pkg/bpffs"
	_ "github.com/iovisor/gobpf/pkg/cpuonline"

	pb "github.com/kinvolk/inspektor-gadget/pkg/gadgettracermanager/api"
)

type GadgetTracerManager struct {
	mu sync.Mutex

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
	mntnsSetMap        *bpflib.Map
	mntnsSetMapPath    string

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
	mntnsSetMapPath := fmt.Sprintf("gadget/mntnsset-%s", tracerId)
	var sectionParams = map[string]bpflib.SectionParams{
		"maps/cgroupid_set": bpflib.SectionParams{
			PinPath: cgroupIdSetMapPath,
		},
		"maps/mntns_set": bpflib.SectionParams{
			PinPath: mntnsSetMapPath,
		},
	}
	err = m.Load(sectionParams)
	if err != nil {
		return nil, err
	}
	cgroupIdSetMap := m.Map("cgroupid_set")
	mntnsSetMap := m.Map("mntns_set")

	matchesCache := []uint64{}

	for _, c := range g.containers {
		if containerSelectorMatches(req.Selector, &c) {
			matchesCache = append(matchesCache, c.CgroupId)
			zero := uint32(0)
			cgroupIdC := uint64(c.CgroupId)
			m.UpdateElement(cgroupIdSetMap, unsafe.Pointer(&cgroupIdC), unsafe.Pointer(&zero), 0)
			mntnsC := uint64(c.Mntns)
			m.UpdateElement(mntnsSetMap, unsafe.Pointer(&mntnsC), unsafe.Pointer(&zero), 0)
		}
	}

	g.tracers[tracerId] = tracer{
		tracerId:           tracerId,
		containerSelector:  *req.Selector,
		mapHolder:          m,
		cgroupIdSetMap:     cgroupIdSetMap,
		cgroupIdSetMapPath: cgroupIdSetMapPath,
		mntnsSetMap:        mntnsSetMap,
		mntnsSetMapPath:    mntnsSetMapPath,
		matchesCache:       matchesCache,
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

	t.mapHolder.Close()
	os.Remove("/sys/fs/bpf/" + t.cgroupIdSetMapPath)
	os.Remove("/sys/fs/bpf/" + t.mntnsSetMapPath)

	delete(g.tracers, tracerID.Id)
	return &pb.RemoveTracerResponse{}, nil
}

func (g *GadgetTracerManager) AddContainer(ctx context.Context, containerDefinition *pb.ContainerDefinition) (*pb.AddContainerResponse, error) {
	if containerDefinition.ContainerId == "" || containerDefinition.CgroupId == 0 {
		return nil, fmt.Errorf("cannot add container: container id or cgroup id not set")
	}
	if _, ok := g.containers[containerDefinition.ContainerId]; ok {
		return nil, fmt.Errorf("container with cgroup id %v already exists", containerDefinition.CgroupId)
	}

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, containerDefinition) {
			t.matchesCache = append(t.matchesCache, containerDefinition.CgroupId)
			cgroupIdC := uint64(containerDefinition.CgroupId)
			mntnsC := uint64(containerDefinition.Mntns)
			zero := uint32(0)
			t.mapHolder.UpdateElement(t.cgroupIdSetMap, unsafe.Pointer(&cgroupIdC), unsafe.Pointer(&zero), 0)
			t.mapHolder.UpdateElement(t.mntnsSetMap, unsafe.Pointer(&mntnsC), unsafe.Pointer(&zero), 0)
		}
	}

	g.containers[containerDefinition.ContainerId] = *containerDefinition
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

	for _, t := range g.tracers {
		if containerSelectorMatches(&t.containerSelector, &c) {
			//TODO: t.matchesCache = remove_from(t.matchesCache, c.CgroupId)
			cgroupIdC := uint64(c.CgroupId)
			mntnsC := uint64(c.Mntns)
			t.mapHolder.DeleteElement(t.cgroupIdSetMap, unsafe.Pointer(&cgroupIdC))
			t.mapHolder.DeleteElement(t.mntnsSetMap, unsafe.Pointer(&mntnsC))
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
