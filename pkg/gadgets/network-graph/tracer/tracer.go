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
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/inspektor-gadget/pkg/rawsock"
)

//go:generate sh -c "echo $CLANG_OS_FLAGS; GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graphmap ./bpf/graphmap.c -- $CLANG_OS_FLAGS -I./bpf/ -target bpf -D__TARGET_ARCH_x86"

//go:generate sh -c "echo $CLANG_OS_FLAGS; GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang graph ./bpf/graph.c -- $CLANG_OS_FLAGS -I./bpf/ -target bpf -D__TARGET_ARCH_x86"

//go:generate sh -c "echo $CLANG_OS_FLAGS; GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang dump ./bpf/dump.c -- $CLANG_OS_FLAGS -I./bpf/ -target bpf -D__TARGET_ARCH_x86"

// /* for htons() and htonl() */
// #include <arpa/inet.h>
// #include "bpf/graph.h"
import "C"

const (
	BPFSocketProgName = "bpf_prog1"
	BPFIterProgName   = "dump_graph"
	BPFMapName        = "graphmap"
	BPFSocketAttach   = 50
)

type Edge struct {
	Key     string
	PktType string
	IP      net.IP
	Proto   string
	Port    int
}

type link struct {
	collectionProg *ebpf.Collection

	sockFd int

	containerQuark uint64

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	mu sync.Mutex

	// collectionMap contains the eBPF map used by the per-netns eBPF programs
	collectionMap *ebpf.Collection
	graphMap      *ebpf.Map

	// collectionIter contains the eBPF iterator. This is a separate
	// collection in case iterators are not supported.
	collectionIter *ebpf.Collection
	dumpIter       *ebpflink.Iter

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link

	nextContainerQuark uint64
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{
		attachments:        make(map[string]*link),
		nextContainerQuark: 1,
	}

	// Load the eBPF map
	specMap, err := loadGraphmap()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}
	t.collectionMap, err = ebpf.NewCollection(specMap)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}
	var ok bool
	t.graphMap, ok = t.collectionMap.Maps[BPFMapName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF map %q", BPFMapName)
	}

	// Load the eBPF iterator, if supported by kernel
	specIter, err := loadDump()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}
	t.collectionIter, err = ebpf.NewCollectionWithOptions(
		specIter,
		ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 100,
			},
			MapReplacements: map[string]*ebpf.Map{
				BPFMapName: t.graphMap,
			},
		},
	)
	if err != nil {
		// eBPF iterators not supported by kernel
		// Fallback: we will iterate eBPF maps from userspace
		log.Warnf("Warning: failed to create BPF collection, fallback to userspace iterators: %s", err)
		return t, nil
	}
	progIter, ok := t.collectionIter.Programs[BPFIterProgName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPFIterProgName)
	}

	t.dumpIter, err = ebpflink.AttachIter(ebpflink.IterOptions{
		Program: progIter,
		Map:     t.collectionMap.Maps[BPFMapName],
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF iterator: %w", err)
	}

	return t, nil
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
) error {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

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

	collProg, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 100,
			},
			MapReplacements: map[string]*ebpf.Map{
				BPFMapName: t.graphMap,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	socketProg, ok := collProg.Programs[BPFSocketProgName]
	if !ok {
		return fmt.Errorf("failed to find BPF program %q", BPFSocketProgName)
	}

	sockFd, err := rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(sockFd, syscall.SOL_SOCKET, BPFSocketAttach, socketProg.FD()); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	l := &link{
		containerQuark: t.nextContainerQuark,
		collectionProg: collProg,
		sockFd:         sockFd,
		users:          1,
	}
	t.attachments[key] = l
	t.nextContainerQuark++

	return nil
}

func (t *Tracer) Pop() ([]Edge, error) {
	if t.dumpIter != nil {
		return t.popIterator()
	} else {
		return t.popFallback()
	}
}

func pktTypeString(pktType int) string {
	// pkttype definitions:
	// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
	var pktTypeNames = []string{
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

func (t *Tracer) popIterator() ([]Edge, error) {
	file, err := t.dumpIter.Open()
	if err != nil {
		return nil, fmt.Errorf("cannot open iter instance: %w", err)
	}
	defer file.Close()

	edges := []Edge{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var containerQuark uint64
		var pktType, proto, port int
		var ipStr string

		text := scanner.Text()
		matchedElems, err := fmt.Sscanf(text, "%d %d %d %d %s",
			&containerQuark,
			&pktType,
			&proto,
			&port,
			&ipStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse %q: %w", text, err)
		}
		if matchedElems != 5 {
			return nil, fmt.Errorf("failed to parse bpf iterator, expected 5 matched elements had %d", matchedElems)
		}
		ip := net.ParseIP(ipStr)

		edges = append(edges, Edge{
			Key:     t.containerQuarkToKey(containerQuark),
			PktType: pktTypeString(pktType),
			IP:      ip,
			Proto:   protoString(proto),
			Port:    port,
		})
	}

	return edges, nil
}

// popFallback extracts data from the eBPF map but without the BPF Iterator
func (t *Tracer) popFallback() ([]Edge, error) {
	edges := []Edge{}
	var prev *C.struct_graph_key_t = nil
	key := C.struct_graph_key_t{}
	err := t.graphMap.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		return []Edge{}, nil
	}

	for {
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, uint32(C.htonl(key.ip)))
		edges = append(edges, Edge{
			Key:     t.containerQuarkToKey(uint64(key.container_quark)),
			PktType: pktTypeString(int(key.pkt_type)),
			IP:      ip,
			Proto:   protoString(int(key.proto)),
			Port:    int(C.htons(key.port)),
		})

		if err := t.graphMap.Delete(key); err != nil {
			return nil, fmt.Errorf("error deleting key: %w", err)
		}

		prev = &key
		if err := t.graphMap.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}
	return edges, nil
}

func (t *Tracer) releaseLink(key string, l *link) {
	unix.Close(l.sockFd)
	l.collectionProg.Close()
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
}
