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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	beespec "github.com/solo-io/bumblebee/pkg/spec"
	orascontent "oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/run/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	mntNsIdType = "mnt_ns_id_t"
)

type Config struct {
	RegistryAuth orascontent.RegistryOptions
	ProgLocation string
	ProgContent  []byte
	MountnsMap   *ebpf.Map
}

type Tracer struct {
	config        *Config
	eventCallback func(*types.Event)

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection

	valueStruct   *btf.Struct
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader
	//printMapValueSize uint32

	links []link.Link
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
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

func (t *Tracer) installTracer() error {
	// Load the spec
	var err error
	t.spec, err = loadSpec(t.config.ProgContent)
	if err != nil {
		return err
	}

	mapReplacements := map[string]*ebpf.Map{}
	consts := map[string]interface{}{}

	printMap, err := getPrintMap(t.spec)
	if err != nil {
		return fmt.Errorf("get print map: %w", err)
	}

	var ok bool
	t.valueStruct, ok = printMap.Value.(*btf.Struct)
	if !ok {
		return fmt.Errorf("BPF map %q does not have BTF info for values", printMap.Name)
	}

	// Almost same hack as in bumblebee/pkg/loader/loader.go
	//t.printMapValueSize = printMap.ValueSize
	switch printMap.Type {
	case ebpf.RingBuf:
		printMap.ValueSize = 0
	case ebpf.PerfEventArray:
		printMap.KeySize = 4
		printMap.ValueSize = 4
	}

	if t.config.MountnsMap != nil {
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
	}

	// Load the ebpf objects
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	t.collection, err = ebpf.NewCollectionWithOptions(t.spec, opts)
	if err != nil {
		return fmt.Errorf("create BPF collection: %w", err)
	}

	m := t.collection.Maps[printMap.Name]
	switch m.Type() {
	case ebpf.RingBuf:
		t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[printMap.Name])
	case ebpf.PerfEventArray:
		t.perfReader, err = perf.NewReader(t.collection.Maps[printMap.Name], gadgets.PerfBufferPages*os.Getpagesize())
	}
	if err != nil {
		return fmt.Errorf("create BPF map reader: %w", err)
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

func (t *Tracer) run(gadgetCtx gadgets.GadgetContext) {
	typ := t.valueStruct

	var mntNsIdstart, mntNsIdend uint32

	// we suppose the same data structure is always used, so we can precalculate the offsets for
	// the mount ns id
	for _, member := range typ.Members {
		if member.Type.TypeName() != mntNsIdType {
			continue
		}

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
	}

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
		//if uint32(len(rawSample)) < t.printMapValueSize {
		//	gadgetCtx.Logger().Errorf("read ring buffer: len(RawSample)=%d!=%d",
		//		len(rawSample), t.printMapValueSize)
		//	return
		//}

		// data will be decoded in the client
		data := rawSample //[:t.printMapValueSize]

		// get mnt_ns_id for enriching the event
		mtn_ns_id := uint64(0)
		if mntNsIdend != 0 {
			buf := bytes.NewBuffer(data[mntNsIdstart:mntNsIdend])
			// TODO: is binary.LittleEndian correct?
			if err := binary.Read(buf, binary.LittleEndian, &mtn_ns_id); err != nil {
				continue
			}
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mtn_ns_id},
			RawData:       data,
		}

		t.eventCallback(&event)
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

	go t.run(gadgetCtx)
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
