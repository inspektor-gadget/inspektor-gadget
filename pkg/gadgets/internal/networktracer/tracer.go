// Copyright 2022-2023 The Inspektor Gadget authors
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

package networktracer

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang dispatcher ./bpf/dispatcher.bpf.c -- $CLANG_OS_FLAGS -I./bpf/ -I../socketenricher/bpf"

const (
	SocketsMapName = "sockets"
)

type attachment struct {
	dispatcherObjs dispatcherObjects

	sockFd int

	// users keeps track of the users' pid that have called Attach(). This can
	// happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	// In both cases, we want to attach the BPF program only once.
	users map[uint32]struct{}
}

type Tracer[Event any] struct {
	socketEnricher *socketenricher.SocketEnricher
	collection     *ebpf.Collection
	prog           *ebpf.Program
	perfRd         *perf.Reader

	// key: network namespace inode number
	// value: Tracelet
	attachments map[uint64]*attachment

	baseEvent    func(ev types.Event) *Event
	processEvent func(rawSample []byte, netns uint64) (*Event, error)
	eventHandler func(ev *Event)
}

func (t *Tracer[Event]) newAttachment(
	pid uint32,
	netns uint64,
) (_ *attachment, err error) {
	a := &attachment{
		sockFd: -1,
		users:  map[uint32]struct{}{pid: {}},
	}
	defer func() {
		if err != nil {
			if a.sockFd != -1 {
				unix.Close(a.sockFd)
			}
			a.dispatcherObjs.Close()
		}
	}()

	dispatcherSpec, err := loadDispatcher()
	if err != nil {
		return nil, err
	}

	u32netns := uint32(netns)
	consts := map[string]interface{}{
		"current_netns": u32netns,
	}
	if err := dispatcherSpec.RewriteConstants(consts); err != nil {
		return nil, fmt.Errorf("RewriteConstants while attaching to pid %d: %w", pid, err)
	}
	dispatcherSpec.Maps["tail_call"].Contents = []ebpf.MapKV{
		{
			Key:   uint32(0),
			Value: uint32(t.prog.FD()),
		},
	}
	opts := ebpf.CollectionOptions{}
	if err = dispatcherSpec.LoadAndAssign(&a.dispatcherObjs, &opts); err != nil {
		return nil, fmt.Errorf("loading ebpf program: %w", err)
	}

	a.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return nil, fmt.Errorf("opening raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(a.sockFd, syscall.SOL_SOCKET, unix.SO_ATTACH_BPF, a.dispatcherObjs.IgNetDisp.FD()); err != nil {
		return nil, fmt.Errorf("attaching BPF program: %w", err)
	}
	return a, nil
}

func NewTracer[Event any](
	spec *ebpf.CollectionSpec,
	bpfProgName string,
	bpfPerfMapName string,
	baseEvent func(ev types.Event) *Event,
	processEvent func(rawSample []byte, netns uint64) (*Event, error),
) (_ *Tracer[Event], err error) {
	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	t := &Tracer[Event]{
		attachments:  make(map[uint64]*attachment),
		baseEvent:    baseEvent,
		processEvent: processEvent,
	}

	defer func() {
		if err != nil {
			if t.perfRd != nil {
				t.perfRd.Close()
			}
			if t.collection != nil {
				t.collection.Close()
			}
			if t.socketEnricher != nil {
				t.socketEnricher.Close()
			}
		}
	}()

	var opts ebpf.CollectionOptions

	// Only create socket enricher if this is used by the tracer
	for _, m := range spec.Maps {
		if m.Name == SocketsMapName {
			t.socketEnricher, err = socketenricher.NewSocketEnricher()
			if err != nil {
				// Non fatal: support kernels without BTF
				log.Errorf("creating socket enricher: %s", err)
			}
			break
		}
	}

	if t.socketEnricher != nil {
		mapReplacements := map[string]*ebpf.Map{}
		mapReplacements[SocketsMapName] = t.socketEnricher.SocketsMap()
		opts.MapReplacements = mapReplacements
	}

	t.collection, err = ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil {
		return nil, fmt.Errorf("creating BPF collection: %w", err)
	}

	t.perfRd, err = perf.NewReader(t.collection.Maps[bpfPerfMapName], gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return nil, fmt.Errorf("getting a perf reader: %w", err)
	}

	var ok bool
	t.prog, ok = t.collection.Programs[bpfProgName]
	if !ok {
		return nil, fmt.Errorf("BPF program %q not found", bpfProgName)
	}

	return t, nil
}

func (t *Tracer[Event]) Attach(pid uint32) error {
	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", pid, err)
	}
	if a, ok := t.attachments[netns]; ok {
		a.users[pid] = struct{}{}
		return nil
	}

	a, err := t.newAttachment(pid, netns)
	if err != nil {
		return fmt.Errorf("creating network tracer attachment for pid %d: %w", pid, err)
	}
	t.attachments[netns] = a

	return nil
}

func (t *Tracer[Event]) SetEventHandler(handler any) {
	if t.eventHandler != nil {
		panic("handler already set")
	}

	nh, ok := handler.(func(ev *Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
	go t.listen(t.perfRd, t.baseEvent, t.processEvent, t.eventHandler)
}

// EventCallback provides support for legacy pkg/gadget-collection
func (t *Tracer[Event]) EventCallback(event any) {
	e, ok := event.(*Event)
	if !ok {
		panic("event handler argument invalid")
	}
	if t.eventHandler == nil {
		return
	}
	t.eventHandler(e)
}

func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	return t.Attach(container.Pid)
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	return t.Detach(container.Pid)
}

func (t *Tracer[Event]) GetMap(name string) *ebpf.Map {
	return t.collection.Maps[name]
}

func (t *Tracer[Event]) listen(
	rd *perf.Reader,
	baseEvent func(ev types.Event) *Event,
	processEvent func(rawSample []byte, netns uint64) (*Event, error),
	eventCallback func(*Event),
) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			eventCallback(baseEvent(types.Err(msg)))
			return
		}

		if record.LostSamples != 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			eventCallback(baseEvent(types.Warn(msg)))
			continue
		}

		if len(record.RawSample) < 4 {
			eventCallback(baseEvent(types.Err("record too small")))
			continue
		}

		// all networking gadgets have netns as first field
		netns := *(*uint32)(unsafe.Pointer(&record.RawSample[0]))
		event, err := processEvent(record.RawSample, uint64(netns))
		if err != nil {
			eventCallback(baseEvent(types.Err(err.Error())))
			continue
		}
		if event == nil {
			continue
		}
		eventCallback(event)
	}
}

func (t *Tracer[Event]) releaseAttachment(netns uint64, a *attachment) {
	unix.Close(a.sockFd)
	a.dispatcherObjs.Close()
	delete(t.attachments, netns)
}

func (t *Tracer[Event]) Detach(pid uint32) error {
	for netns, a := range t.attachments {
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

func (t *Tracer[Event]) Close() {
	if t.perfRd != nil {
		t.perfRd.Close()
	}
	if t.collection != nil {
		t.collection.Close()
	}
	for key, l := range t.attachments {
		t.releaseAttachment(key, l)
	}
	if t.socketEnricher != nil {
		t.socketEnricher.Close()
	}
}
