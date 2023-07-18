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
	"context"
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
	"github.com/solo-io/bumblebee/pkg/decoder"
	beespec "github.com/solo-io/bumblebee/pkg/spec"
	orascontent "oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// keep aligned with pkg/gadgets/common/types.h
type l3EndpointT struct {
	addr    [16]byte
	version uint8
	pad     [3]uint8
}

type l4EndpointT struct {
	l3   l3EndpointT
	port uint16
}

type Config struct {
	RegistryAuth orascontent.RegistryOptions
	ProgLocation string
	ProgContent  []byte
	MountnsMap   *ebpf.Map
}

type Tracer struct {
	config         *Config
	eventCallback  func(*types.Event)
	decoderFactory decoder.DecoderFactory

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection
	// Type describing the format the gadget uses
	eventType *btf.Struct

	// Printers related
	printMap          *ebpf.MapSpec
	ringbufReader     *ringbuf.Reader
	perfReader        *perf.Reader
	printMapValueSize uint32

	links []link.Link
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config:         &Config{},
		decoderFactory: decoder.NewDecoderFactory(),
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	return nil
}

// Close is needed because of the StartStopGadget interface
func (t *Tracer) Close() {
}

func (t *Tracer) getByobEbpfPackage() (*beespec.EbpfPackage, error) {
	localRegistry := orascontent.NewMemory()

	remoteRegistry, err := orascontent.NewRegistry(t.config.RegistryAuth)
	if err != nil {
		return nil, fmt.Errorf("create new oras registry: %w", err)
	}

	_, err = oras.Copy(
		context.Background(),
		remoteRegistry,
		t.config.ProgLocation,
		localRegistry,
		t.config.ProgLocation,
	)
	if err != nil {
		return nil, fmt.Errorf("copy oras: %w", err)
	}
	byobClient := beespec.NewEbpfOCICLient()
	return byobClient.Pull(context.Background(), t.config.ProgLocation, localRegistry)
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
}

func (t *Tracer) handlePrint() error {
	var err error
	t.printMap, err = getPrintMap(t.spec)
	if err != nil {
		// It's possible the the program doesn't define any print map. Don't return an error
		// in that case.
		return nil
	}

	eventType, ok := t.printMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("BPF map %q does not have BTF info for values", t.printMap.Name)
	}
	t.eventType = eventType

	// Almost same hack as in bumblebee/pkg/loader/loader.go
	t.printMapValueSize = t.printMap.ValueSize
	switch t.printMap.Type {
	case ebpf.RingBuf:
		t.printMap.ValueSize = 0
	case ebpf.PerfEventArray:
		t.printMap.KeySize = 4
		t.printMap.ValueSize = 4
	}

	return nil
}

func (t *Tracer) installTracer() error {
	// Load the spec
	var err error
	t.spec, err = loadSpec(t.config.ProgContent)
	if err != nil {
		return err
	}

	mapReplacements := map[string]*ebpf.Map{}
	consts := map[string]interface{}{}

	if err := t.handlePrint(); err != nil {
		return fmt.Errorf("handling print_ programs: %w", err)
	}

	if t.eventType == nil {
		return fmt.Errorf("the gadget doesn't provide event type information")
	}

	// Handle special maps like mount ns filter, socket enricher, etc.
	for _, m := range t.spec.Maps {
		// Replace filter mount ns map
		if m.Name == gadgets.MntNsFilterMapName {
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
	if t.printMap != nil {
		m := t.collection.Maps[t.printMap.Name]
		switch m.Type() {
		case ebpf.RingBuf:
			t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[t.printMap.Name])
		case ebpf.PerfEventArray:
			t.perfReader, err = perf.NewReader(t.collection.Maps[t.printMap.Name], gadgets.PerfBufferPages*os.Getpagesize())
		}
		if err != nil {
			return fmt.Errorf("create BPF map reader: %w", err)
		}
	}

	// Attach programs
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
		}
	}

	return nil
}

// processEventFunc returns a callback that parses a binary encoded event in data, enriches and
// returns it.
func (t *Tracer) processEventFunc(gadgetCtx gadgets.GadgetContext) func(data []byte) *types.Event {
	typ := t.eventType

	var mntNsIdstart, mntNsIdend uint32

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

	// we suppose the same data structure is always used, so we can precalculate the offsets for
	// the mount ns id
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
			mntNsIdend = mntNsIdstart + intM.Size
		case gadgets.L3EndpointTypeName:
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L3}
			endpointDefs = append(endpointDefs, e)
		case gadgets.L4EndpointTypeName:
			e := endpointDef{name: member.Name, start: member.Offset.Bytes(), typ: L4}
			endpointDefs = append(endpointDefs, e)
		}
	}

	return func(data []byte) *types.Event {
		// get mnt_ns_id for enriching the event
		mtn_ns_id := uint64(0)
		if mntNsIdend != 0 {
			mtn_ns_id = *(*uint64)(unsafe.Pointer(&data[mntNsIdstart]))
		}

		// enrich endpoints
		l3endpoints := []types.L3Endpoint{}
		l4endpoints := []types.L4Endpoint{}

		for _, endpoint := range endpointDefs {
			endpointC := (*l3EndpointT)(unsafe.Pointer(&data[endpoint.start]))
			var addr string
			switch endpointC.version {
			case 4:
				ipBytes := make(net.IP, 4)
				copy(ipBytes, endpointC.addr[:])
				addr = ipBytes.String()
			case 6:
				ipBytes := make(net.IP, 16)
				copy(ipBytes, endpointC.addr[:])
				addr = ipBytes.String()
			default:
				gadgetCtx.Logger().Warnf("bad IP version received: %d", endpointC.version)
				continue
			}

			l3endpoint := eventtypes.L3Endpoint{
				Addr:    addr,
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

func (t *Tracer) runPrint(gadgetCtx gadgets.GadgetContext) {
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

		// TODO: this check is not valid for all cases. For instance trace exec sends a variable length
		if uint32(len(rawSample)) < t.printMapValueSize {
			gadgetCtx.Logger().Errorf("read ring buffer: len(RawSample)=%d!=%d",
				len(rawSample), t.printMapValueSize)
			return
		}

		// data will be decoded in the client
		data := rawSample[:t.printMapValueSize]
		ev := cb(data)
		t.eventCallback(ev)
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	if len(params.Get(ProgramContent).AsBytes()) != 0 {
		t.config.ProgContent = params.Get(ProgramContent).AsBytes()
	} else {
		args := gadgetCtx.Args()
		if len(args) != 1 {
			return fmt.Errorf("expected exactly one argument, got %d", len(args))
		}

		param := args[0]
		t.config.ProgLocation = param
		// Download the BPF module
		byobEbpfPackage, err := t.getByobEbpfPackage()
		if err != nil {
			return fmt.Errorf("download byob ebpf package: %w", err)
		}
		t.config.ProgContent = byobEbpfPackage.ProgramFileBytes
	}

	if err := t.installTracer(); err != nil {
		t.Stop()
		return fmt.Errorf("install tracer: %w", err)
	}

	if t.printMap != nil {
		go t.runPrint(gadgetCtx)
	}
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
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
