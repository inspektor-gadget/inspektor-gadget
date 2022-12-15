// Copyright 2019-2022 The Inspektor Gadget authors
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
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/network/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graphmap ./bpf/graphmap.c -- $CLANG_OS_FLAGS -I./bpf/"

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graph ./bpf/graph.c -- $CLANG_OS_FLAGS -I./bpf/"

const (
	BPFSocketAttach = 50
)

type attachment struct {
	networkGraphObjects graphObjects

	sockFd int

	// users keeps track of the users' pid that have called Attach(). This can
	// happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	// In both cases, we want to attach the BPF program only once.
	users map[uint32]struct{}
}

type Tracer struct {
	// networkGraphMapObjects contains the eBPF map used by the per-netns eBPF programs
	networkGraphMapObjects graphmapObjects

	// key: network namespace inode number
	// value: Tracelet
	attachments map[uint64]*attachment

	enricher gadgets.DataEnricherByNetNs

	// Cache to store already enriched events from terminated (detached)
	// containers.
	sync.Mutex
	cache []*types.Event
}

func NewTracer(enricher gadgets.DataEnricherByNetNs) (_ *Tracer, err error) {
	t := &Tracer{
		attachments: make(map[uint64]*attachment),
		enricher:    enricher,
	}
	defer func() {
		if err != nil {
			// bpf2go objects can safely be closed even when not initialized
			t.networkGraphMapObjects.Close()
		}
	}()

	// Load the eBPF map
	specMap, err := loadGraphmap()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}
	if err := specMap.LoadAndAssign(&t.networkGraphMapObjects, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	return t, nil
}

func (t *Tracer) Attach(pid uint32) (err error) {
	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return fmt.Errorf("getting network namespace of pid %d: %w", pid, err)
	}
	if a, ok := t.attachments[netns]; ok {
		a.users[pid] = struct{}{}
		return nil
	}

	a := &attachment{
		users:  map[uint32]struct{}{pid: {}},
		sockFd: -1,
	}
	defer func() {
		if err != nil {
			// bpf2go objects can safely be closed even when not initialized
			a.networkGraphObjects.Close()
			if a.sockFd != -1 {
				unix.Close(a.sockFd)
			}
		}
	}()

	spec, err := loadGraph()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	consts := map[string]interface{}{
		"container_netns": netns,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	if err := spec.LoadAndAssign(
		&a.networkGraphObjects,
		&ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"graphmap": t.networkGraphMapObjects.graphmapMaps.Graphmap,
			},
		},
	); err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	if a.sockFd, err = rawsock.OpenRawSock(pid); err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(
		a.sockFd,
		syscall.SOL_SOCKET, BPFSocketAttach,
		a.networkGraphObjects.graphPrograms.IgTraceNet.FD(),
	); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	t.attachments[netns] = a

	return nil
}

func pktTypeString(pktType int) string {
	// pkttype definitions:
	// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
	pktTypeNames := []string{
		"HOST",
		"BROADCAST",
		"MULTICAST",
		"OTHERHOST",
		"OUTGOING",
		"LOOPBACK",
		"USER",
		"KERNEL",
	}
	pktTypeStr := fmt.Sprintf("UNKNOWN#%d", pktType)
	if uint(pktType) < uint(len(pktTypeNames)) {
		pktTypeStr = pktTypeNames[pktType]
	}
	return pktTypeStr
}

func protoString(proto int) string {
	// proto definitions:
	// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
	protoStr := fmt.Sprintf("UNKNOWN#%d", proto)
	switch proto {
	case 6:
		protoStr = "tcp"
	case 17:
		protoStr = "udp"
	}
	return protoStr
}

func (t *Tracer) Pop() (events []*types.Event, err error) {
	defer func() {
		if err != nil {
			return
		}

		l := len(t.cache)
		if l == 0 {
			return
		}

		log.Debugf("appending %d elements to the resulting events from cache", l)

		t.Lock()
		defer t.Unlock()
		events = append(events, t.cache...)
		t.cache = nil
	}()

	convertKeyToEvent := func(key graphmapGraphKeyT, val uint64) *types.Event {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, gadgets.Htonl(key.Ip))
		e := &types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(val),
			},
			PktType:    pktTypeString(int(key.PktType)),
			Proto:      protoString(int(key.Proto)),
			Port:       gadgets.Htons(key.Port),
			RemoteAddr: ip.String(),
		}

		if t.enricher != nil {
			t.enricher.EnrichByNetNs(&e.CommonData, key.ContainerNetns)
		}
		return e
	}

	graphmap := t.networkGraphMapObjects.graphmapMaps.Graphmap

	for {
		nextKey := graphmapGraphKeyT{}
		deleteKeys := make([]graphmapGraphKeyT, 256)
		deleteValues := make([]uint64, 256)
		count, err := graphmap.BatchLookupAndDelete(nil, &nextKey, deleteKeys, deleteValues, nil)
		for i := 0; i < count; i++ {
			events = append(events, convertKeyToEvent(deleteKeys[i], deleteValues[i]))
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return events, nil
		}
		if errors.Is(err, ebpf.ErrNotSupported) {
			// Fallback to iteration & deletion without batch
			break
		}
		if err != nil {
			return nil, fmt.Errorf("error in BPF batch operation: %w", err)
		}
	}

	key := graphmapGraphKeyT{}
	val := uint64(0)
	entries := graphmap.Iterate()

	for entries.Next(&key, &val) {
		events = append(events, convertKeyToEvent(key, val))

		// Deleting an entry during the iteration causes the iteration
		// to restart from the first key in the hash map. But in this
		// case, this is not a problem since we're deleting everything
		// unconditionally.
		if err := graphmap.Delete(key); err != nil {
			return nil, fmt.Errorf("error deleting key: %w", err)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("error iterating on map: %w", err)
	}
	return events, nil
}

func (t *Tracer) releaseAttachment(netns uint64, a *attachment) {
	unix.Close(a.sockFd)
	a.networkGraphObjects.Close()
	delete(t.attachments, netns)
}

func (t *Tracer) populateCache() error {
	events, err := t.Pop()
	if err != nil {
		return fmt.Errorf("popping events: %w", err)
	}

	l := len(events)
	if l == 0 {
		return nil
	}

	log.Debugf("caching %d events", l)

	t.Lock()
	defer t.Unlock()
	t.cache = append(t.cache, events...)

	return nil
}

func (t *Tracer) Detach(pid uint32) error {
	for netns, a := range t.attachments {
		if _, ok := a.users[pid]; ok {
			delete(a.users, pid)
			if len(a.users) == 0 {
				t.releaseAttachment(netns, a)
			}

			// Before returning, read and enrich the events in the GraphMap to
			// ensure EnrichByNetNs() is still able to retrieve the metadata of
			// the container that is being detached. Otherwise, by the time
			// Pop() will be called, the container might have been already
			// deleted, and EnrichByNetNs() won't be able to enrich its events
			// anymore.
			if err := t.populateCache(); err != nil {
				log.Errorf("caching events while detaching pid %d: %v", pid, err)
			}

			return nil
		}
	}

	return fmt.Errorf("pid %d is not attached", pid)
}

func (t *Tracer) Close() {
	for key, l := range t.attachments {
		t.releaseAttachment(key, l)
	}
	t.networkGraphMapObjects.Close()
}
