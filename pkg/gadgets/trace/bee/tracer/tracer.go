//go:build linux
// +build linux

// Copyright 2022 The Inspektor Gadget authors
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

package tracer

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/solo-io/bumblebee/pkg/decoder"
	beespec "github.com/solo-io/bumblebee/pkg/spec"
	"golang.org/x/sys/unix"
	orascontent "oras.land/oras-go/pkg/content"
	"oras.land/oras-go/pkg/oras"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	socketenricher "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/enricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bee/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
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

type networkLink struct {
	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	config         *Config
	enricher       gadgets.DataEnricher
	eventCallback  func(types.Event)
	decoderFactory decoder.DecoderFactory

	spec                 *ebpf.CollectionSpec
	collection           *ebpf.Collection
	socketFilterPrograms []*ebpf.Program

	socketEnricher *socketenricher.SocketsMap
	socketsMap     *ebpf.Map

	printMap      string
	valueStruct   *btf.Struct
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader

	mapSizes map[string]uint32
	links    []link.Link

	// key: namespace/podname
	// value: Tracelet
	networkAttachments map[string]*networkLink
}

func NewTracer(config *Config, enricher gadgets.DataEnricher,
	eventCallback func(types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:         config,
		enricher:       enricher,
		eventCallback:  eventCallback,
		decoderFactory: decoder.NewDecoderFactory(),

		mapSizes: make(map[string]uint32),

		networkAttachments: make(map[string]*networkLink),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) getBeeEbpfPackage() (*beespec.EbpfPackage, error) {
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
		//oras.WithAllowedMediaTypes(beespec.AllowedMediaTypes()),
		//oras.WithPullByBFS,
	)
	if err != nil {
		fmt.Printf("Copy: %v\n", err)
		return nil, err
	}
	beeClient := beespec.NewEbpfOCICLient()
	return beeClient.Pull(context.Background(), t.config.ProgLocation, localRegistry)
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

func (t *Tracer) start() error {
	if len(t.config.ProgContent) == 0 {
		// Download the BPF module
		beeEbpfPackage, err := t.getBeeEbpfPackage()
		if err != nil {
			return fmt.Errorf("failed to download bee ebpf package: %w", err)
		}
		t.config.ProgContent = beeEbpfPackage.ProgramFileBytes
	}

	// Load the spec
	progReader := bytes.NewReader(t.config.ProgContent)
	var err error
	t.spec, err = ebpf.LoadCollectionSpecFromReader(progReader)
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}

	// Find the print map
	for mapName, m := range t.spec.Maps {
		//if strings.Contains(m.SectionName, "print") || strings.Contains(m.SectionName, "counter") {
		if m.Type == ebpf.RingBuf || m.Type == ebpf.PerfEventArray {
			if t.printMap != "" {
				return fmt.Errorf("multiple print maps: %q and %q", t.printMap, mapName)
			}
			t.printMap = mapName

			var ok bool
			t.valueStruct, ok = m.Value.(*btf.Struct)
			if !ok {
				return fmt.Errorf("BPF map %q does not have BTF info for values", mapName)
			}
		}

		// Same hack as in bumblebee/pkg/loader/loader.go
		if m.Type == ebpf.RingBuf || m.Type == ebpf.PerfEventArray {
			//t.spec.Maps[mapName].BTF = nil
			t.mapSizes[mapName] = t.spec.Maps[mapName].ValueSize
			t.spec.Maps[mapName].ValueSize = 0
		}

		if m.Type == ebpf.Hash && mapName == "sockets" && strings.Contains(m.SectionName, ".auto") {
			fmt.Printf("found map %q. Starting enricher\n", mapName)

			t.socketEnricher, err = socketenricher.NewSocketsMap()
			if err != nil {
				return fmt.Errorf("failed to start socket enricher: %w", err)
			}
			t.socketsMap = t.socketEnricher.SocketsMap()
			mapReplacements["sockets"] = t.socketsMap
		}
	}
	if t.printMap == "" {
		return fmt.Errorf("no BPF map named 'print'")
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
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	m := t.collection.Maps[t.printMap]
	if m.Type() == ebpf.RingBuf {
		t.ringbufReader, err = ringbuf.NewReader(t.collection.Maps[t.printMap])
	} else if m.Type() == ebpf.PerfEventArray {
		t.perfReader, err = perf.NewReader(t.collection.Maps[t.printMap], gadgets.PerfBufferPages*os.Getpagesize())
	} else {
		return fmt.Errorf("unsupported BPF map type: %s", m.Type())
	}
	if err != nil {
		return fmt.Errorf("failed to create BPF map reader: %w", err)
	}
	go t.run()

	// Attach programs
	for progName, p := range t.spec.Programs {
		if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kprobe/") {
			l, err := link.Kprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("failed to attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.Kprobe && strings.HasPrefix(p.SectionName, "kretprobe/") {
			l, err := link.Kretprobe(p.AttachTo, t.collection.Programs[progName], nil)
			if err != nil {
				return fmt.Errorf("failed to attach BPF program %q: %w", progName, err)
			}
			t.links = append(t.links, l)
		} else if p.Type == ebpf.SocketFilter && strings.HasPrefix(p.SectionName, "socket") {
			t.socketFilterPrograms = append(t.socketFilterPrograms, t.collection.Programs[progName])
		}
	}

	return nil
}

func (t *Tracer) run() {
	d := t.decoderFactory()
	ctx := context.TODO()
	for {
		var rawSample []byte

		if t.ringbufReader != nil {
			record, err := t.ringbufReader.Read()
			if err != nil {
				if errors.Is(err, ringbuf.ErrClosed) {
					// nothing to do, we're done
					return
				}

				msg := fmt.Sprintf("Error reading ring buffer: %s", err)
				t.eventCallback(types.Base(eventtypes.Err(msg)))
				return
			}
			rawSample = record.RawSample
		} else if t.perfReader != nil {
			record, err := t.perfReader.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					return
				}

				msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
				t.eventCallback(types.Base(eventtypes.Err(msg)))
				return
			}

			if record.LostSamples != 0 {
				msg := fmt.Sprintf("lost %d samples", record.LostSamples)
				t.eventCallback(types.Base(eventtypes.Warn(msg)))
				continue
			}
			rawSample = record.RawSample
		} else {
			msg := fmt.Sprintf("Error using reader for ring buffer")
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if uint32(len(rawSample)) < t.mapSizes[t.printMap] {
			msg := fmt.Sprintf("Error reading ring buffer: len(RawSample)=%d!=%d",
				len(rawSample),
				t.mapSizes[t.printMap])
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}
		result, err := d.DecodeBtfBinary(ctx, t.valueStruct, rawSample[:t.mapSizes[t.printMap]])
		if err != nil {
			msg := fmt.Sprintf("Error decoding btf: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}
		b, err := json.Marshal(result)
		if err != nil {
			msg := fmt.Sprintf("Error encoding json: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			MountNsID: uint64(0),
			Payload:   fmt.Sprintf("%+v", string(b)),
		}

		if t.enricher != nil {
			t.enricher.Enrich(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(event)
	}
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
	eventCallback func(types.Event),
) (err error) {
	if l, ok := t.networkAttachments[key]; ok {
		l.users++
		return nil
	}

	l := &networkLink{
		sockFd: -1,
		users:  1,
	}
	defer func() {
		if err != nil {
			if l.sockFd != -1 {
				unix.Close(l.sockFd)
			}
		}
	}()

	l.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	for _, prog := range t.socketFilterPrograms {
		if err := syscall.SetsockoptInt(l.sockFd, syscall.SOL_SOCKET, BPFSocketAttach, prog.FD()); err != nil {
			return fmt.Errorf("failed to attach BPF program: %w", err)
		}
	}

	t.networkAttachments[key] = l

	return nil
}

func (t *Tracer) releaseLink(key string, l *networkLink) {
	unix.Close(l.sockFd)
	delete(t.networkAttachments, key)
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.networkAttachments[key]; ok {
		l.users--
		if l.users == 0 {
			t.releaseLink(key, l)
		}
		return nil
	} else {
		return fmt.Errorf("key not attached: %q", key)
	}
}

func (t *Tracer) Close() {
	for key, l := range t.networkAttachments {
		t.releaseLink(key, l)
	}
}
