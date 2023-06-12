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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/byob/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

const (
	BPFSocketAttach = 50
)

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

	printMap      string
	valueStruct   *btf.Struct
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader

	mapSizes  map[string]uint32
	links     []link.Link
	linksIter []*link.Iter
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config:         &Config{},
		mapSizes:       make(map[string]uint32),
		decoderFactory: decoder.NewDecoderFactory(),
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.ProgLocation = params.Get(ParamOCIImage).AsString()

	if len(t.config.ProgLocation) != 0 {
		// Download the BPF module
		byobEbpfPackage, err := t.getByobEbpfPackage()
		if err != nil {
			return fmt.Errorf("download byob ebpf package: %w", err)
		}
		t.config.ProgContent = byobEbpfPackage.ProgramFileBytes
	} else if len(params.Get(ProgramContent).AsBytes()) != 0 {
		t.config.ProgContent = params.Get(ProgramContent).AsBytes()
	} else {
		return fmt.Errorf("%q or %q not set", ParamOCIImage, ProgramContent)
	}

	if err := t.installTracer(); err != nil {
		return fmt.Errorf("install tracer: %w", err)
	}

	return nil
}

func (t *Tracer) Close() {
	t.collection.Close()
}

func (t *Tracer) getByobEbpfPackage() (*beespec.EbpfPackage, error) {
	localRegistry := orascontent.NewMemory()

	remoteRegistry, err := orascontent.NewRegistry(t.config.RegistryAuth)
	if err != nil {
		fmt.Printf("NewRegistry: %v\n", err)
		return nil, err
	}

	_, err = oras.Copy(
		context.Background(),
		remoteRegistry,
		t.config.ProgLocation,
		localRegistry,
		t.config.ProgLocation,
	)
	if err != nil {
		fmt.Printf("Copy: %v\n", err)
		return nil, err
	}
	byobClient := beespec.NewEbpfOCICLient()
	return byobClient.Pull(context.Background(), t.config.ProgLocation, localRegistry)
}

func (t *Tracer) Stop() {
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
	progReader := bytes.NewReader(t.config.ProgContent)
	var err error
	t.spec, err = ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return fmt.Errorf("load ebpf program: %w", err)
	}

	fmt.Printf("Spec:\n%+v\n", t.spec)
	btfEntries := t.spec.Types.Iterate()

	var (
		i                      int64 = 0
		iEntryPlaceholder      int64 = -1
		iEntryPlaceholderInner int64 = -1
		iEntryTask             int64 = -1
		iEntryCred             int64 = -1
		iMemberCred            int64 = -1
		memberCredOffset       int64 = -1
		typeCred               btf.Type
		typeTask               btf.Type
	)

	for btfEntries.Next() {
		fmt.Printf("Type #%d %q: %+v\n", i, btfEntries.Type.TypeName(), btfEntries.Type)
		if btfEntries.Type.TypeName() == "placeholder_struct" {
			iEntryPlaceholder = i
		}
		if btfEntries.Type.TypeName() == "placeholder_inner_field" {
			iEntryPlaceholderInner = i
		}
		if btfEntries.Type.TypeName() == "task_struct" {
			iEntryTask = i
			typeTask = btfEntries.Type
			for j, field := range typeTask.(*btf.Struct).Members {
				if field.Name == "cred" {
					iMemberCred = int64(j)
					memberCredOffset = int64(field.Offset.Bytes())
				}
				fmt.Printf("task_struct field #%d: %+v\n", j, field.Name)
			}
		}
		if btfEntries.Type.TypeName() == "cred" {
			iEntryCred = i
			typeCred = btfEntries.Type
		}
		i++
	}
	fmt.Printf("i task->cred: %d->%d placeholder_struct->inner_field=%d->%d iMemberCred=%d\n",
		iEntryTask, iEntryCred,
		iEntryPlaceholder, iEntryPlaceholderInner,
		iMemberCred,
	)

	for progName, p := range t.spec.Programs {
		fmt.Printf("Program %q: %+v\n", progName, p)
		for i, ins := range p.Instructions {
			src := ins.Source()
			if src != nil {
				fmt.Printf("; %s\n", src.String())
			}
			fmt.Printf("Instruction #%d: %+v\n", i, ins)
			relo := btf.CORERelocationMetadata(&ins)
			if relo != nil {
				fmt.Printf("  constant=%d relo: %s\n", ins.Constant, relo.String())
				if strings.HasPrefix(relo.String(), "placeholder_inner_field 0 target_type_id ") && ins.Constant == iEntryPlaceholderInner {
					p.Instructions[i].Constant = iEntryCred
					relo.Update(typeCred, "0", "", btf.TypeID(iEntryCred))
					fmt.Printf("  --> Replaced instruction [cred] #%d: %+v\n", i, p.Instructions[i])
				}
				if strings.HasPrefix(relo.String(), "placeholder_struct 0:0 byte_off ") {
					p.Instructions[i].Constant = memberCredOffset
					relo.Update(typeTask, fmt.Sprintf("0:%d", iMemberCred), "byte_off", btf.TypeID(iEntryTask))
					fmt.Printf("  --> Replaced instruction [task] #%d: %+v\n", i, p.Instructions[i])
				}
			}
		}
	}

	mapReplacements := map[string]*ebpf.Map{}

	// Find the print map
	for mapName, m := range t.spec.Maps {
		// TODO: Print maps only with prefix print_ ?
		if (m.Type == ebpf.RingBuf || m.Type == ebpf.PerfEventArray) && strings.HasPrefix(m.Name, "print_") {
			if t.printMap != "" {
				return fmt.Errorf("multiple print maps: %q and %q", t.printMap, mapName)
			}
			t.printMap = mapName

			var ok bool
			t.valueStruct, ok = m.Value.(*btf.Struct)
			if !ok {
				return fmt.Errorf("BPF map %q does not have BTF info for values", mapName)
			}

			// Almost same hack as in bumblebee/pkg/loader/loader.go
			t.mapSizes[mapName] = t.spec.Maps[mapName].ValueSize
			if m.Type == ebpf.RingBuf {
				t.spec.Maps[mapName].ValueSize = 0
			} else if m.Type == ebpf.PerfEventArray {
				t.spec.Maps[mapName].KeySize = 4
				t.spec.Maps[mapName].ValueSize = 4
			}
		}
	}

	// Load the ebpf objects
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 5000,
		},
		MapReplacements: mapReplacements,
	}
	t.collection, err = ebpf.NewCollectionWithOptions(t.spec, opts)
	if err != nil {
		var errVerifier *ebpf.VerifierError
		if errors.As(err, &errVerifier) {
			fmt.Printf("Verifier error: %+v\n",
				errVerifier)
		}
		return fmt.Errorf("create BPF collection: %w", err)
	}
	if t.printMap != "" {
		m := t.collection.Maps[t.printMap]
		switch m.Type() {
		case ebpf.RingBuf:
			t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[t.printMap])
		case ebpf.PerfEventArray:
			t.perfReader, err = perf.NewReader(t.collection.Maps[t.printMap], gadgets.PerfBufferPages*os.Getpagesize())
		default:
			return fmt.Errorf("unsupported BPF map type: %q", m.Type())
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
		} else if p.Type == ebpf.Tracing && strings.HasPrefix(p.SectionName, "iter/") {
			switch p.AttachTo {
			case "task":
				l, err := link.AttachIter(link.IterOptions{
					Program: t.collection.Programs[progName],
				})
				if err != nil {
					return fmt.Errorf("attach BPF program %q: %w", progName, err)
				}
				t.linksIter = append(t.linksIter, l)
				t.links = append(t.links, l)
			}
		}
	}

	return nil
}

func (t *Tracer) runIter(gadgetCtx gadgets.GadgetContext) {
	for {
		for _, l := range t.linksIter {
			file, err := l.Open()
			if err != nil {
				gadgetCtx.Logger().Errorf("open BPF link: %w", err)
				return
			}
			defer file.Close()
			buf, err := io.ReadAll(file)
			if err != nil {
				gadgetCtx.Logger().Errorf("read BPF link: %w", err)
				return
			}
			fmt.Printf("%s\n", string(buf))
		}
		time.Sleep(1 * time.Second)
	}
}

func (t *Tracer) run(gadgetCtx gadgets.GadgetContext) {
	d := t.decoderFactory()
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
		} else {
			gadgetCtx.Logger().Error("neither ring buffer or perf ring buffer was found")
			return
		}

		if uint32(len(rawSample)) < t.mapSizes[t.printMap] {
			gadgetCtx.Logger().Errorf("read ring buffer: len(RawSample)=%d!=%d",
				len(rawSample),
				t.mapSizes[t.printMap])
			return
		}

		// FIXME: DecodeBtfBinary has a bug with non-NULL-terminated strings.
		// For now, ensure the problem does not happen in ebpf

		result, err := d.DecodeBtfBinary(gadgetCtx.Context(), t.valueStruct, rawSample[:t.mapSizes[t.printMap]])
		if err != nil {
			gadgetCtx.Logger().Errorf("decoding btf: %w", err)
			return
		}
		b, err := json.Marshal(result)
		if err != nil {
			gadgetCtx.Logger().Errorf("encoding json: %w", err)
			return
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: 0},
			Payload:       fmt.Sprintf("%+v", string(b)),
		}

		if mnt_ns_id_str, ok := result["mnt_ns_id"]; ok {
			if mnt_ns_id, ok := mnt_ns_id_str.(uint64); ok {
				event.MountNsID = mnt_ns_id
			}
		}
		t.eventCallback(&event)
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	go t.run(gadgetCtx)
	go t.runIter(gadgetCtx)
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
