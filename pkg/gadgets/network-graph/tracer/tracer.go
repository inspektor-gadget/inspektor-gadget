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
	"bytes"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"

	"github.com/cilium/ebpf"
	ebpflink "github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/kinvolk/inspektor-gadget/pkg/rawsock"
)

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
	collection *ebpf.Collection

	dumpIter *ebpflink.Iter

	sockFd int

	containerQuark uint64

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	mu sync.Mutex

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link

	pinPath string

	nextContainerQuark uint64
}

func NewTracer(pinPath string) (*Tracer, error) {
	os.Remove(filepath.Join(pinPath, BPFMapName))
	os.MkdirAll(pinPath, 0750)

	t := &Tracer{
		attachments:        make(map[string]*link),
		pinPath:            pinPath,
		nextContainerQuark: 1,
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

	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	consts := map[string]interface{}{
		"container_quark": t.nextContainerQuark,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	coll, err := ebpf.NewCollectionWithOptions(
		spec,
		ebpf.CollectionOptions{
			Programs: ebpf.ProgramOptions{
				LogSize: ebpf.DefaultVerifierLogSize * 100,
			},
			Maps: ebpf.MapOptions{
				PinPath: t.pinPath,
			},
		},
	)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	socketProg, ok := coll.Programs[BPFSocketProgName]
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

	iterProg, ok := coll.Programs[BPFIterProgName]
	if !ok {
		return fmt.Errorf("failed to find BPF program %q", BPFIterProgName)
	}

	dumpIter, err := ebpflink.AttachIter(ebpflink.IterOptions{
		Program: iterProg,
		Map:     coll.Maps[BPFMapName],
	})
	if err != nil {
		return fmt.Errorf("failed to attach BPF iterator: %w", err)
	}

	l := &link{
		containerQuark: t.nextContainerQuark,
		collection:     coll,
		sockFd:         sockFd,
		dumpIter:       dumpIter,
		users:          1,
	}
	t.attachments[key] = l
	t.nextContainerQuark++

	return nil
}

func (t *Tracer) Pop() ([]Edge, error) {
	// FIXME: fix concurrent access

	var dumpIter *ebpflink.Iter
	for _, v := range t.attachments {
		dumpIter = v.dumpIter
		break
	}
	if dumpIter == nil {
		return nil, nil
	}

	file, err := dumpIter.Open()
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

		key := "NotFound"
		for k, v := range t.attachments {
			if containerQuark == v.containerQuark {
				key = k
				break
			}
		}

		// pkttype definitions:
		// https://github.com/torvalds/linux/blob/v5.14-rc7/include/uapi/linux/if_packet.h#L26
		pktTypeStr := fmt.Sprintf("UNKNOWN#%d", pktType)
		switch pktType {
		case 0:
			pktTypeStr = "HOST"
		case 4:
			pktTypeStr = "PACKET_OUTGOING"
		}

		// proto definitions:
		// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
		protoStr := fmt.Sprintf("UNKNOWN#%d", proto)
		switch proto {
		case 6:
			protoStr = "tcp"
		case 17:
			protoStr = "udp"
		}

		edges = append(edges, Edge{
			Key:     key,
			PktType: pktTypeStr,
			IP:      ip,
			Proto:   protoStr,
			Port:    port,
		})
	}

	return edges, nil
}

func (t *Tracer) releaseLink(key string, l *link) {
	unix.Close(l.sockFd)
	l.collection.Close()
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
	os.Remove(filepath.Join(t.pinPath, BPFMapName))
}
