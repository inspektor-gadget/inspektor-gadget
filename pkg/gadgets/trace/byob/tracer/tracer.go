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
	"io"
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

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/byob/types"
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

	spec       *ebpf.CollectionSpec
	collection *ebpf.Collection

	plugCloser io.Closer

	users map[uint32]struct{}
}

type Tracer struct {
	config         *Config
	enricher       gadgets.DataEnricher
	eventCallback  func(types.Event)
	decoderFactory decoder.DecoderFactory

	spec                 *ebpf.CollectionSpec
	collection           *ebpf.Collection
	socketFilterPrograms []string

	socketEnricher *socketenricher.SocketEnricher
	socketsMap     *ebpf.Map

	printMap      string
	valueStruct   *btf.Struct
	ringbufReader *ringbuf.Reader
	perfReader    *perf.Reader

	mapSizes map[string]uint32
	links    []link.Link

	// key: netns
	// value: Tracelet
	networkAttachments map[uint64]*networkLink
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

		networkAttachments: make(map[uint64]*networkLink),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
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
		// oras.WithAllowedMediaTypes(beespec.AllowedMediaTypes()),
		// oras.WithPullByBFS,
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

func (t *Tracer) start() error {
	if len(t.config.ProgContent) == 0 {
		// Download the BPF module
		byobEbpfPackage, err := t.getByobEbpfPackage()
		if err != nil {
			return fmt.Errorf("failed to download byob ebpf package: %w", err)
		}
		t.config.ProgContent = byobEbpfPackage.ProgramFileBytes
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
		// if strings.Contains(m.SectionName, "print") || strings.Contains(m.SectionName, "counter") {
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
			// t.spec.Maps[mapName].BTF = nil
			t.mapSizes[mapName] = t.spec.Maps[mapName].ValueSize
			t.spec.Maps[mapName].ValueSize = 4
			// Needed for MapReplacements
			t.spec.Maps[mapName].KeySize = 4
		}

		if m.Type == ebpf.Hash && mapName == "sockets" && strings.Contains(m.SectionName, ".auto") {
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
			t.socketFilterPrograms = append(t.socketFilterPrograms, progName)
		}
	}

	t.socketEnricher, err = socketenricher.NewSocketsMap()
	if err != nil {
		return fmt.Errorf("failed to start socket enricher: %w", err)
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

		// FIXME: DecodeBtfBinary has a bug with non-NULL-terminated strings.
		// For now, ensure the problem does not happen in ebpf

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
		var mountNsIDStruct struct {
			MountNsID uint64 `json:"mount_ns_id"`
		}
		_ = json.Unmarshal(b, &mountNsIDStruct)
		event.MountNsID = mountNsIDStruct.MountNsID

		if t.enricher != nil {
			t.enricher.Enrich(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(event)
	}
}

// Attach attaches networking programs in the netns related to the pid
//
// Tracing programs (like kprobes) are attached once during start() but
// networking programs are attached for each netns.
func (t *Tracer) Attach(
	pid uint32,
	eventCallback func(types.Event),
) (err error) {
	if len(t.socketFilterPrograms) == 0 {
		// The BPF program does not have networking programs.
		// Nothing to do.
		return nil
	}

	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", pid, err)
	}

	if a, ok := t.networkAttachments[netns]; ok {
		a.users[pid] = struct{}{}
		return nil
	}

	a := &networkLink{
		sockFd: -1,
		users:  make(map[uint32]struct{}),
	}
	defer func() {
		if err != nil {
			if a.sockFd != -1 {
				unix.Close(a.sockFd)
			}
		}
	}()

	a.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	a.spec = t.spec.Copy()

	// Load the ebpf objects. We can't reuse t.collection because we want
	// to have distinct global constants such as current_netns.

	consts := map[string]interface{}{
		"current_netns": netns,
	}

	if err := a.spec.RewriteConstants(consts); err != nil && !strings.Contains(err.Error(), "spec is missing one or more constants") {
		return fmt.Errorf("error RewriteConstants while attaching to pid %d: %w", pid, err)
	}

	mapReplacements := map[string]*ebpf.Map{
		// Reuse the print map, so we don't need to setup a new go
		// routine to read a ring buffer for each netns.
		t.printMap: t.collection.Maps[t.printMap],
	}
	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			LogSize: ebpf.DefaultVerifierLogSize * 5000,
		},
		MapReplacements: mapReplacements,
	}

	a.collection, err = ebpf.NewCollectionWithOptions(a.spec, opts)
	if err != nil {
		var errVerifier *ebpf.VerifierError
		if errors.As(err, &errVerifier) {
			fmt.Printf("Verifier error: %+v\n",
				errVerifier)
		}
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	for _, progName := range t.socketFilterPrograms {
		closer, err := t.socketEnricher.PlugExtension(a.collection.Programs[progName], netns)
		if err != nil {
			return fmt.Errorf("failed to plug extension: %w", err)
		}
		a.plugCloser = closer

		if err := syscall.SetsockoptInt(a.sockFd, syscall.SOL_SOCKET, BPFSocketAttach, a.collection.Programs[progName].FD()); err != nil {
			return fmt.Errorf("failed to attach BPF program: %w", err)
		}
	}

	t.networkAttachments[netns] = a

	return nil
}

func (t *Tracer) releaseAttachment(netns uint64, a *networkLink) {
	unix.Close(a.sockFd)
	a.plugCloser.Close()
	a.collection.Close()
	delete(t.networkAttachments, netns)
}

func (t *Tracer) Detach(pid uint32) error {
	for netns, a := range t.networkAttachments {
		if _, ok := a.users[pid]; ok {
			delete(a.users, pid)
			if len(a.users) == 0 {
				t.releaseAttachment(netns, a)
			}
			return nil
		}
	}
	return fmt.Errorf("pid %d is not attached", pid)
}

func (t *Tracer) Close() {
	for pid, a := range t.networkAttachments {
		t.releaseAttachment(pid, a)
	}
	t.collection.Close()
}
