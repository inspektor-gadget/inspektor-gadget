// Copyright 2023 The Inspektor Gadget authors
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

//go:build !withoutebpf

package tracer

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// keep aligned with pkg/gadgets/common/types.h
type l3EndpointT struct {
	addr    [16]byte
	version uint8
	pad     [3]uint8 // manual padding to avoid issues between C and Go
}

type l4EndpointT struct {
	l3    l3EndpointT
	port  uint16
	proto uint16
}

type Config struct {
	ProgContent []byte
	Metadata    *types.GadgetMetadata
	MountnsMap  *ebpf.Map
}

type Tracer struct {
	config        *Config
	eventCallback func(*types.Event)

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	// Type describing the format the gadget uses
	eventType *btf.Struct

	socketEnricher *socketenricher.SocketEnricher
	networkTracer  *networktracer.Tracer[types.Event]

	// Tracers related
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader

	links []link.Link
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	// FIXME: Ideally, we should have one networktracer.NewTracer per socket
	//        filter program. But in NewInstance(), we don't have access to
	//        the ebpf program yet, so we don't know how many socket filters
	//        we have. For now, we don't support several socket filter.
	//        Currently, we unfortunately impact performance with the
	//        networkTracer even if there are no socket filters. This is
	//        difficult to fix because AttachContainer() is called for all
	//        initial containers before Run(), so we need to create the
	//        networkTracer in NewInstance().
	// https://github.com/inspektor-gadget/inspektor-gadget/pull/2003#discussion_r1320569238
	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return nil, fmt.Errorf("creating network tracer: %w", err)
	}

	tracer := &Tracer{
		config:        &Config{},
		networkTracer: networkTracer,
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	return nil
}

// Close is needed because of the StartStopGadget interface
func (t *Tracer) Close() {
}

func (t *Tracer) Stop() {
	if t.collection != nil {
		t.collection.Close()
		t.collection = nil
	}
	for _, l := range t.links {
		gadgets.CloseLink(l)
	}
	t.links = nil

	if t.ringbufReader != nil {
		t.ringbufReader.Close()
	}
	if t.perfReader != nil {
		t.perfReader.Close()
	}
	if t.socketEnricher != nil {
		t.socketEnricher.Close()
	}
}

func (t *Tracer) handleTraceMap() (*ebpf.MapSpec, error) {
	// If the gadget doesn't provide a map it's not an error becuase it could provide other ways
	// to output data
	traceMap := getTracerMap(t.spec, t.config.Metadata)
	if traceMap == nil {
		return nil, nil
	}

	eventType, ok := traceMap.Value.(*btf.Struct)
	if !ok {
		return nil, fmt.Errorf("BPF map %q does not have BTF info for values", traceMap.Name)
	}
	t.eventType = eventType

	// Almost same hack as in https://github.com/solo-io/bumblebee/blob/c2422b5bab66754b286d062317e244f02a431dac/pkg/loader/loader.go#L114-L120
	// TODO: Remove it?
	switch traceMap.Type {
	case ebpf.RingBuf:
		traceMap.ValueSize = 0
	case ebpf.PerfEventArray:
		traceMap.KeySize = 4
		traceMap.ValueSize = 4
	}

	return traceMap, nil
}

func (t *Tracer) installTracer() error {
	// Load the spec
	var err error

	mapReplacements := map[string]*ebpf.Map{}
	consts := map[string]interface{}{}

	traceMap, err := t.handleTraceMap()
	if err != nil {
		return fmt.Errorf("handling trace programs: %w", err)
	}

	if t.eventType == nil {
		return fmt.Errorf("the gadget doesn't provide event type information")
	}

	// Handle special maps like mount ns filter, socket enricher, etc.
	for _, m := range t.spec.Maps {
		switch m.Name {
		// Only create socket enricher if this is used by the tracer
		case socketenricher.SocketsMapName:
			t.socketEnricher, err = socketenricher.NewSocketEnricher()
			if err != nil {
				// Containerized gadgets require a kernel with BTF
				return fmt.Errorf("creating socket enricher: %w", err)
			}
			mapReplacements[socketenricher.SocketsMapName] = t.socketEnricher.SocketsMap()
		// Replace filter mount ns map
		case gadgets.MntNsFilterMapName:
			if t.config.MountnsMap == nil {
				break
			}

			mapReplacements[gadgets.MntNsFilterMapName] = t.config.MountnsMap
			consts[gadgets.FilterByMntNsName] = true
		}
	}

	if err := t.spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	// Load the ebpf objects
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	t.collection, err = ebpf.NewCollectionWithOptions(t.spec, opts)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	// Some logic before loading the programs
	if traceMap != nil {
		m := t.collection.Maps[traceMap.Name]
		switch m.Type() {
		case ebpf.RingBuf:
			t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[traceMap.Name])
		case ebpf.PerfEventArray:
			t.perfReader, err = perf.NewReader(t.collection.Maps[traceMap.Name], gadgets.PerfBufferPages*os.Getpagesize())
		}
		if err != nil {
			return fmt.Errorf("create BPF map reader: %w", err)
		}
	}

	// Attach programs
	socketFilterFound := false
	for progName, p := range t.spec.Programs {
		if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kprobe/") {
			l, err := link.Kprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kretprobe/") {
			l, err := link.Kretprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.TracePoint && strings.HasPrefix(p.SectionName, "tracepoint/") {
			parts := strings.Split(p.AttachTo, "/")
			l, err := link.Tracepoint(parts[0], parts[1], t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.SocketFilter && strings.HasPrefix(p.SectionName, "socket") {
			if socketFilterFound {
				return fmt.Errorf("several socket filters found, only one is supported")
			}
			socketFilterFound = true
			err := t.networkTracer.AttachProg(t.collection.Programs[progName])
			if err != nil {
				return fmt.Errorf("attaching ebpf program to dispatcher: %w", err)
			}
		}
	}

	return nil
}

// processEventFunc returns a callback that parses a binary encoded event in data, enriches and
// returns it.
func (t *Tracer) processEventFunc(gadgetCtx gadgets.GadgetContext) func(data []byte) *types.Event {
	typ := t.eventType

	var mntNsIdstart uint32
	mountNsIdFound := false

	type endpointType int

	const (
		U endpointType = iota
		L3
		L4
	)

	type endpointDef struct {
		name  string
		start uint32
		typ   endpointType
	}

	endpointDefs := []endpointDef{}

	// The same same data structure is always sent, so we can precalculate the offsets for
	// different fields like mount ns id, endpoints, etc.
	for _, member := range typ.Members {
		switch member.Type.TypeName() {
		case gadgets.MntNsIdTypeName:
			typDef, ok := member.Type.(*btf.Typedef)
			if !ok {
				continue
			}

			underlying, err := getUnderlyingType(typDef)
			if err != nil {
				continue
			}

			intM, ok := underlying.(*btf.Int)
			if !ok {
				continue
			}

			if intM.Size != 8 {
				continue
			}

			mntNsIdstart = member.Offset.Bytes()
			mountNsIdFound = true
		case gadgets.L3EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				gadgetCtx.Logger().Warn("%s is not a struct", member.Name)
				continue
			}
			if typ.Size != uint32(unsafe.Sizeof(l3EndpointT{})) {
				gadgetCtx.Logger().Warn("%s is not the expected size", member.Name)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L3}
			endpointDefs = append(endpointDefs, e)
		case gadgets.L4EndpointTypeName:
			typ, ok := member.Type.(*btf.Struct)
			if !ok {
				gadgetCtx.Logger().Warn("%s is not a struct", member.Name)
				continue
			}
			if typ.Size != uint32(unsafe.Sizeof(l4EndpointT{})) {
				gadgetCtx.Logger().Warn("%s is not the expected size", member.Name)
				continue
			}
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L4}
			endpointDefs = append(endpointDefs, e)
		}
	}

	return func(data []byte) *types.Event {
		// get mnt_ns_id for enriching the event
		mtn_ns_id := uint64(0)
		if mountNsIdFound {
			mtn_ns_id = *(*uint64)(unsafe.Pointer(&data[mntNsIdstart]))
		}

		// enrich endpoints
		l3endpoints := []types.L3Endpoint{}
		l4endpoints := []types.L4Endpoint{}

		for _, endpoint := range endpointDefs {
			endpointC := (*l3EndpointT)(unsafe.Pointer(&data[endpoint.start]))
			var size int
			switch endpointC.version {
			case 4:
				size = 4
			case 6:
				size = 16
			default:
				gadgetCtx.Logger().Warnf("bad IP version received: %d", endpointC.version)
				continue
			}

			ipBytes := make(net.IP, size)
			copy(ipBytes, endpointC.addr[:])

			l3endpoint := eventtypes.L3Endpoint{
				Addr:    ipBytes.String(),
				Version: endpointC.version,
			}

			switch endpoint.typ {
			case L3:
				endpoint := types.L3Endpoint{
					Name:       endpoint.name,
					L3Endpoint: l3endpoint,
				}
				l3endpoints = append(l3endpoints, endpoint)
			case L4:
				l4EndpointC := (*l4EndpointT)(unsafe.Pointer(&data[endpoint.start]))
				endpoint := types.L4Endpoint{
					Name: endpoint.name,
					L4Endpoint: eventtypes.L4Endpoint{
						L3Endpoint: l3endpoint,
						Port:       l4EndpointC.port,
						Proto:      l4EndpointC.proto,
					},
				}
				l4endpoints = append(l4endpoints, endpoint)
			}
		}

		return &types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mtn_ns_id},
			RawData:       data,
			L3Endpoints:   l3endpoints,
			L4Endpoints:   l4endpoints,
		}
	}
}

func (t *Tracer) runTracers(gadgetCtx gadgets.GadgetContext) {
	cb := t.processEventFunc(gadgetCtx)

	for {
		var rawSample []byte

		if t.ringbufReader != nil {
			record, err := t.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// nothing to do, we're done
					return
				}
				gadgetCtx.Logger().Errorf("read ring buffer: %w", err)
				return
			}
			rawSample = record.RawSample
		} else if t.perfReader != nil {
			record, err := t.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}
				gadgetCtx.Logger().Errorf("read perf ring buffer: %w", err)
				return
			}

			if record.LostSamples != 0 {
				gadgetCtx.Logger().Warnf("lost %d samples", record.LostSamples)
				continue
			}
			rawSample = record.RawSample
		}

		ev := cb(rawSample)
		t.eventCallback(ev)
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	args := gadgetCtx.Args()

	info, err := getGadgetInfo(params, args, gadgetCtx.Logger())
	if err != nil {
		return fmt.Errorf("getting gadget info: %w", err)
	}

	t.config.ProgContent = info.ProgContent
	t.spec, err = loadSpec(t.config.ProgContent)
	if err != nil {
		return err
	}

	t.config.Metadata = info.GadgetMetadata

	if err := t.installTracer(); err != nil {
		t.Stop()
		return fmt.Errorf("install tracer: %w", err)
	}

	if t.perfReader != nil || t.ringbufReader != nil {
		go t.runTracers(gadgetCtx)
	}
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	return t.networkTracer.Attach(container.Pid)
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	return t.networkTracer.Detach(container.Pid)
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}
