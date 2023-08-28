// Copyright 2021-2023 The Inspektor Gadget authors
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
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	socketcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/socket/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type entry  socket ./bpf/socket.bpf.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c

type Tracer struct {
	iters []*link.Iter

	// visitedNamespaces is a map where the key is the netns inode number and
	// the value is the pid of one of the containers that share that netns. Such
	// pid is used by NetnsEnter. TODO: Improve NetnsEnter to also work with the
	// netns directly.
	visitedNamespaces map[uint64]uint32
	protocols         socketcollectortypes.Proto
	eventHandler      func([]*socketcollectortypes.Event)
}

func parseIPv4(ipU32 uint32) string {
	ipBytes := make([]byte, 4)

	// net.IP() expects network byte order and parseIPv4 receives an
	// argument in host byte order, so it needs to be converted first
	binary.BigEndian.PutUint32(ipBytes, ipU32)
	ip := net.IP(ipBytes)

	return ip.String()
}

// Format from socket_bpf_seq_print() in bpf/socket_common.h
func parseStatus(proto string, statusUint uint8) (string, error) {
	statusMap := [...]string{
		"ESTABLISHED", "SYN_SENT", "SYN_RECV",
		"FIN_WAIT1", "FIN_WAIT2", "TIME_WAIT", "CLOSE", "CLOSE_WAIT",
		"LAST_ACK", "LISTEN", "CLOSING", "NEW_SYN_RECV",
	}

	// Kernel enum starts from 1, adjust it to the statusMap
	if statusUint == 0 || len(statusMap) <= int(statusUint-1) {
		return "", fmt.Errorf("invalid %s status: %d", proto, statusUint)
	}
	status := statusMap[statusUint-1]

	// Transform TCP status into something more suitable for UDP
	if proto == "UDP" {
		switch status {
		case "ESTABLISHED":
			status = "ACTIVE"
		case "CLOSE":
			status = "INACTIVE"
		default:
			return "", fmt.Errorf("unexpected %s status %s", proto, status)
		}
	}

	return status, nil
}

func (t *Tracer) runCollector(pid uint32, netns uint64) ([]*socketcollectortypes.Event, error) {
	sockets := []*socketcollectortypes.Event{}
	err := netnsenter.NetnsEnter(int(pid), func() error {
		for _, it := range t.iters {
			reader, err := it.Open()
			if err != nil {
				return fmt.Errorf("opening BPF iterator: %w", err)
			}
			defer reader.Close()

			buf, err := io.ReadAll(reader)
			if err != nil {
				return fmt.Errorf("reading BPF iterator: %w", err)
			}
			entrySize := int(unsafe.Sizeof(socketEntry{}))

			for i := 0; i < len(buf)/entrySize; i++ {
				entry := (*socketEntry)(unsafe.Pointer(&buf[i*entrySize]))

				proto := eventtypes.ProtoToString(entry.Proto)
				status, err := parseStatus(proto, entry.State)
				if err != nil {
					return err
				}

				event := &socketcollectortypes.Event{
					Event: eventtypes.Event{
						Type: eventtypes.NORMAL,
					},
					Protocol: proto,
					SrcEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: parseIPv4(entry.Saddr),
						},
						Port: entry.Sport,
					},
					DstEndpoint: eventtypes.L4Endpoint{
						L3Endpoint: eventtypes.L3Endpoint{
							Addr: parseIPv4(entry.Daddr),
						},
						Port: entry.Dport,
					},
					Status:      status,
					InodeNumber: entry.Inode,
					WithNetNsID: eventtypes.WithNetNsID{NetNsID: netns},
				}

				sockets = append(sockets, event)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	return sockets, nil
}

// RunCollector is currently exported so it can be called from Collect(). It can be removed once
// pkg/gadget-collection/gadgets/snapshot/socket/gadget.go is gone.
func (t *Tracer) RunCollector(pid uint32, podname, namespace, node string) ([]*socketcollectortypes.Event, error) {
	netns, err := containerutils.GetNetNs(int(pid))
	if err != nil {
		return nil, fmt.Errorf("getting netns for pid %d: %w", pid, err)
	}

	sockets, err := t.runCollector(pid, netns)
	if err != nil {
		return nil, err
	}

	for _, socket := range sockets {
		socket.K8s.Node = node
		socket.K8s.Namespace = namespace
		socket.K8s.PodName = podname
	}

	return sockets, nil
}

// ---

func NewTracer(protocols socketcollectortypes.Proto) (*Tracer, error) {
	tracer := &Tracer{
		visitedNamespaces: make(map[uint64]uint32),
		protocols:         protocols,
	}

	if err := tracer.openIters(); err != nil {
		tracer.CloseIters()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return tracer, nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{
		visitedNamespaces: make(map[uint64]uint32),
	}, nil
}

func (t *Tracer) AttachContainer(container *containercollection.Container) error {
	if _, ok := t.visitedNamespaces[container.Netns]; ok {
		return nil
	}
	t.visitedNamespaces[container.Netns] = container.Pid
	return nil
}

func (t *Tracer) DetachContainer(container *containercollection.Container) error {
	return nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*socketcollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

// CloseIters is currently exported so it can be called from Collect()
func (t *Tracer) CloseIters() {
	for _, it := range t.iters {
		it.Close()
	}
	t.iters = nil
}

func (t *Tracer) openIters() error {
	// TODO: how to avoid loading programs that aren't needed?
	objs := &socketObjects{}
	if err := loadSocketObjects(objs, nil); err != nil {
		return err
	}

	toAttach := []*ebpf.Program{}

	switch t.protocols {
	case socketcollectortypes.TCP:
		toAttach = append(toAttach, objs.IgSnapTcp4)
	case socketcollectortypes.UDP:
		toAttach = append(toAttach, objs.IgSnapUdp4)
	case socketcollectortypes.ALL:
		toAttach = append(toAttach, objs.IgSnapTcp4, objs.IgSnapUdp4)
	}

	for _, prog := range toAttach {
		it, err := link.AttachIter(link.IterOptions{
			Program: prog,
		})
		if err != nil {
			var name string
			if info, err := prog.Info(); err == nil {
				name = info.Name
			}
			return fmt.Errorf("attaching program %q: %w", name, err)
		}
		t.iters = append(t.iters, it)
	}

	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	protocols := gadgetCtx.GadgetParams().Get(ParamProto).AsString()
	t.protocols = socketcollectortypes.ProtocolsMap[protocols]

	defer t.CloseIters()
	if err := t.openIters(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	allSockets := []*socketcollectortypes.Event{}
	for netns, pid := range t.visitedNamespaces {
		sockets, err := t.runCollector(pid, netns)
		if err != nil {
			return fmt.Errorf("snapshotting sockets in netns %d: %w", netns, err)
		}
		allSockets = append(allSockets, sockets...)
	}

	t.eventHandler(allSockets)
	return nil
}
