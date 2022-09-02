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
	"syscall"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/inspektor-gadget/pkg/rawsock"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graphmap ./bpf/graphmap.c -- $CLANG_OS_FLAGS -I./bpf/"

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graph ./bpf/graph.c -- $CLANG_OS_FLAGS -I./bpf/"

// /* for htons() and htonl() */
// #include <arpa/inet.h>
import "C"

const (
	BPFSocketAttach = 50
)

type Edge struct {
	Key     string
	PktType string
	IP      net.IP
	Proto   string
	Port    int
}

type link struct {
	networkGraphObjects graphObjects

	sockFd int

	containerQuark uint64

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	// networkGraphMapObjects contains the eBPF map used by the per-netns eBPF programs
	networkGraphMapObjects graphmapObjects

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link

	nextContainerQuark uint64
}

func NewTracer() (_ *Tracer, err error) {
	t := &Tracer{
		attachments:        make(map[string]*link),
		nextContainerQuark: 1,
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

func (t *Tracer) Attach(key string, pid uint32) (err error) {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	l := &link{
		containerQuark: t.nextContainerQuark,
		users:          1,
		sockFd:         -1,
	}
	defer func() {
		if err != nil {
			// bpf2go objects can safely be closed even when not initialized
			l.networkGraphObjects.Close()
			if l.sockFd != -1 {
				unix.Close(l.sockFd)
			}
		}
	}()

	spec, err := loadGraph()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	consts := map[string]interface{}{
		"container_quark": t.nextContainerQuark,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	if err := spec.LoadAndAssign(
		&l.networkGraphObjects,
		&ebpf.CollectionOptions{
			MapReplacements: map[string]*ebpf.Map{
				"graphmap": t.networkGraphMapObjects.graphmapMaps.Graphmap,
			},
		},
	); err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	if l.sockFd, err = rawsock.OpenRawSock(pid); err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(
		l.sockFd,
		syscall.SOL_SOCKET, BPFSocketAttach,
		l.networkGraphObjects.graphPrograms.IgTraceNet.FD(),
	); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	t.attachments[key] = l
	t.nextContainerQuark++

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

func (t *Tracer) containerQuarkToKey(quark uint64) string {
	key := "NotFound"
	for k, v := range t.attachments {
		if quark == v.containerQuark {
			key = k
			break
		}
	}
	return key
}

func (t *Tracer) Pop() ([]Edge, error) {
	graphmap := t.networkGraphMapObjects.graphmapMaps.Graphmap
	edges := []Edge{}

	convertKeyToEdge := func(key graphmapGraphKeyT) Edge {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(C.htonl(C.uint(key.Ip))))
		return Edge{
			Key:     t.containerQuarkToKey(uint64(key.ContainerQuark)),
			PktType: pktTypeString(int(key.PktType)),
			IP:      ip,
			Proto:   protoString(int(key.Proto)),
			Port:    int(C.htons(C.ushort(key.Port))),
		}
	}

	for {
		nextKey := graphmapGraphKeyT{}
		deleteKeys := make([]graphmapGraphKeyT, 256)
		deleteValues := make([]uint64, 256)
		count, err := graphmap.BatchLookupAndDelete(nil, &nextKey, deleteKeys, deleteValues, nil)
		for i := 0; i < count; i++ {
			edges = append(edges, convertKeyToEdge(deleteKeys[i]))
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return edges, nil
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
		edges = append(edges, convertKeyToEdge(key))

		// Deleting an entry during the iteration causes the iteration
		// to restart from the first key in the hash map. But in this
		// case, this is not a problem since we're deleting everything
		// inconditionally.
		if err := graphmap.Delete(key); err != nil {
			return nil, fmt.Errorf("error deleting key: %w", err)
		}
	}
	if err := entries.Err(); err != nil {
		return nil, fmt.Errorf("error iterating on map: %w", err)
	}
	return edges, nil
}

func (t *Tracer) releaseLink(key string, l *link) {
	unix.Close(l.sockFd)
	l.networkGraphObjects.Close()
	delete(t.attachments, key)
}

func (t *Tracer) Detach(key string) error {
	if l, ok := t.attachments[key]; ok {
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
	for key, l := range t.attachments {
		t.releaseLink(key, l)
	}
	t.networkGraphMapObjects.Close()
}
