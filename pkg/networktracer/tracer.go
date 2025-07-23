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

// Package networktracer installs the dispatcher ebpf program in each network
// namespace of interest. The dispatcher program runs a tail call to the actual
// gadget program.
//
// This is done both for builtin gadgets and containerized gadgets. In the case
// of containerized gadgets, the dispatcher program is installed before
// knowing the actual gadget program. Once it knows the actual gadget program,
// the tail call map is updated.
//
// In the case of builtin gadgets, the Run() method can be called to fetch and
// process events from ebpf. The containerized gadgets won't call Run() because
// run/tracer.go fetches and processes the events themselves. Instead, it will
// just call AttachProg().
//
// The actual gadget program is instantiated only once for performance reason.
// The network namespace is passed to the actual gadget program via the
// skb->cb[0] variable.
//
// https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/devel/network-gadget-dispatcher.png
package networktracer

import (
	"fmt"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} dispatcher ./bpf/dispatcher.bpf.c -- -I./bpf/ -I../socketenricher/bpf

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
	socketEnricherMap *ebpf.Map
	dispatcherMap     *ebpf.Map
	collection        *ebpf.Collection
	prog              *ebpf.Program
	perfRd            *perf.Reader

	// key: network namespace inode number
	// value: Tracelet
	attachments map[uint64]*attachment

	eventHandler func(ev *Event)

	// mu protects attachments from concurrent access
	// AttachContainer and DetachContainer can be called in parallel
	mu sync.Mutex
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

	spec, err := loadDispatcher()
	if err != nil {
		return nil, err
	}
	dispatcherSpec := &dispatcherSpecs{}
	if err := spec.Assign(dispatcherSpec); err != nil {
		return nil, err
	}

	if err := dispatcherSpec.CurrentNetns.Set(uint32(netns)); err != nil {
		return nil, err
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: map[string]*ebpf.Map{
			"tail_call": t.dispatcherMap,
		},
	}
	if err = spec.LoadAndAssign(&a.dispatcherObjs, &opts); err != nil {
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

func NewTracer[Event any]() (_ *Tracer[Event], err error) {
	t := &Tracer[Event]{
		attachments: make(map[uint64]*attachment),
	}

	// Keep in sync with tail_call map in bpf/dispatcher.bpf.c
	dispatcherMapSpec := ebpf.MapSpec{
		Name:       "tail_call",
		Type:       ebpf.ProgramArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	t.dispatcherMap, err = ebpf.NewMap(&dispatcherMapSpec)
	if err != nil {
		return nil, fmt.Errorf("creating tail_call map: %w", err)
	}
	return t, nil
}

// AttachProg is used directly by containerized gadgets
func (t *Tracer[Event]) AttachProg(prog *ebpf.Program) error {
	return t.dispatcherMap.Update(uint32(0), uint32(prog.FD()), ebpf.UpdateAny)
}

func (t *Tracer[Event]) Attach(pid uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()

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

func (t *Tracer[Event]) AttachContainer(container *containercollection.Container) error {
	return t.Attach(container.ContainerPid())
}

func (t *Tracer[Event]) DetachContainer(container *containercollection.Container) error {
	return t.Detach(container.ContainerPid())
}

func (t *Tracer[Event]) releaseAttachment(netns uint64, a *attachment) {
	unix.Close(a.sockFd)
	a.dispatcherObjs.Close()
	delete(t.attachments, netns)
}

func (t *Tracer[Event]) Detach(pid uint32) error {
	t.mu.Lock()
	defer t.mu.Unlock()

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
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.perfRd != nil {
		t.perfRd.Close()
	}
	if t.collection != nil {
		t.collection.Close()
	}
	for key, l := range t.attachments {
		t.releaseAttachment(key, l)
	}
	if t.dispatcherMap != nil {
		t.dispatcherMap.Close()
	}
}
