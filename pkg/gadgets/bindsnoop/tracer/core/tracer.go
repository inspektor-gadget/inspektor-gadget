//go:build linux
// +build linux

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

// #include <linux/types.h>
// #include "./bpf/bindsnoop.h"
// #include <arpa/inet.h>
// #include <stdlib.h>
//
//char *ip_to_string(const struct bind_event *event) {
//	socklen_t size;
//	int ip_type;
//	char *ip;
//
//	if (event->ver == 4)
//		ip_type = AF_INET;
//	else if (event->ver == 6)
//		ip_type = AF_INET6;
//	else
//		return NULL;
//
//	size = sizeof *ip * INET6_ADDRSTRLEN;
//	ip = malloc(size);
//  if (ip == NULL)
//		return NULL;
//
//	inet_ntop(ip_type, &event->addr, ip, size);
//
//	return ip;
//}
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/bindsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
	"github.com/vishvananda/netlink"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang bindsnoop ./bpf/bindsnoop.bpf.c -- -I./bpf/ -I../../../../ -target bpf -D__TARGET_ARCH_x86"

type Tracer struct {
	config        *tracer.Config
	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string

	objs      bindsnoopObjects
	ipv4Entry link.Link
	ipv4Exit  link.Link
	ipv6Entry link.Link
	ipv6Exit  link.Link
	reader    *perf.Reader
}

func NewTracer(config *tracer.Config, resolver containercollection.ContainerResolver,
	eventCallback func(types.Event), node string,
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		resolver:      resolver,
		eventCallback: eventCallback,
		node:          node,
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.ipv4Entry = gadgets.CloseLink(t.ipv4Entry)
	t.ipv4Exit = gadgets.CloseLink(t.ipv4Exit)
	t.ipv6Entry = gadgets.CloseLink(t.ipv6Entry)
	t.ipv6Exit = gadgets.CloseLink(t.ipv6Exit)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadBindsnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
	}

	filterByPort := false
	if len(t.config.TargetPorts) > 0 {
		filterByPort = true

		m := spec.Maps["ports"]
		for _, port := range t.config.TargetPorts {
			m.Contents = append(m.Contents, ebpf.MapKV{Key: port, Value: port})
		}
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
		"target_pid":       t.config.TargetPid,
		"filter_by_port":   filterByPort,
		"ignore_errors":    t.config.IgnoreErrors,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.ipv4Entry, err = link.Kprobe("inet_bind", t.objs.Ipv4BindEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}

	t.ipv4Exit, err = link.Kretprobe("inet_bind", t.objs.Ipv4BindExit, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv4 kprobe: %w", err)
	}

	t.ipv6Entry, err = link.Kprobe("inet6_bind", t.objs.Ipv6BindEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}

	t.ipv6Exit, err = link.Kretprobe("inet6_bind", t.objs.Ipv6BindExit, nil)
	if err != nil {
		return fmt.Errorf("error opening ipv6 kprobe: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.bindsnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}

	go t.run()

	return nil
}

// optionsToString translates options bitfield to a string containing a letter
// if the option is set or a dot.
// It is a translation of opts2array added in this commit of kinvolk/bcc:
// 9621f010e33c ("tools/bindsnoop: add support for --json")
func optionsToString(options uint8) string {
	ret := ""
	bit := uint8(1)

	for _, option := range []string{"F", "T", "N", "R", "r"} {
		if (options & bit) != 0 {
			ret = option + ret
		} else {
			ret = "." + ret
		}
		bit <<= 1
	}

	return ret
}

// Taken from:
// https://elixir.bootlin.com/linux/v5.16.10/source/include/uapi/linux/in.h#L28
var socketProtocol = map[uint16]string{
	0:   "IP",       // Dummy protocol for TCP
	1:   "ICMP",     // Internet Control Message Protocol
	2:   "IGMP",     // Internet Group Management Protocol
	4:   "IPIP",     // IPIP tunnels (older KA9Q tunnels use 94)
	6:   "TCP",      // Transmission Control Protocol
	8:   "EGP",      // Exterior Gateway Protocol
	12:  "PUP",      // PUP protocol
	17:  "UDP",      // User Datagram Protocol
	22:  "IDP",      // XNS IDP protocol
	29:  "TP",       // SO Transport Protocol Class 4
	33:  "DCCP",     // Datagram Congestion Control Protocol
	41:  "IPV6",     // IPv6-in-IPv4 tunnelling
	46:  "RSVP",     // RSVP Protocol
	47:  "GRE",      // Cisco GRE tunnels (rfc 1701,1702)
	50:  "ESP",      // Encapsulation Security Payload protocol
	51:  "AH",       // Authentication Header protocol
	92:  "MTP",      // Multicast Transport Protocol
	94:  "BEETPH",   // IP option pseudo header for BEET
	98:  "ENCAP",    // Encapsulation Header
	103: "PIM",      // Protocol Independent Multicast
	108: "COMP",     // Compression Header Protocol
	132: "SCTP",     // Stream Control Transport Protocol
	136: "UDPLITE",  // UDP-Lite (RFC 3828)
	137: "MPLS",     // MPLS in IP (RFC 4023)
	143: "ETHERNET", // Ethernet-within-IPv6 Encapsulation
	255: "RAW",      // Raw IP packets
	262: "MPTCP",    // Multipath TCP connection
}

// protocolToString translates a kernel protocol enum value to the protocol
// name.
func protocolToString(protocol uint16) string {
	protocolString, ok := socketProtocol[protocol]
	if !ok {
		protocolString = "UNKNOWN"
	}

	return protocolString
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg, t.node)))
			continue
		}

		eventC := (*C.struct_bind_event)(unsafe.Pointer(&record.RawSample[0]))

		addr := C.ip_to_string(eventC)
		defer C.free(unsafe.Pointer(addr))

		interfaceString := "0"
		interfaceNum := int(eventC.bound_dev_if)
		if interfaceNum != 0 {
			// It does exist a net link which index is 0.
			// But eBPF bindsnoop code often gives 0 as interface number:
			// https://github.com/iovisor/bcc/blob/63618552f81a2631990eff59fd7460802c58c30b/tools/bindsnoop_example.txt#L16
			// So, we only use this function if interface number is different than 0.
			interf, err := netlink.LinkByIndex(interfaceNum)
			if err != nil {
				msg := fmt.Sprintf("Cannot get net interface for %d : %s", interfaceNum, err)
				t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
				return
			}

			interfaceString = interf.Attrs().Name
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
			},
			Pid:       uint32(eventC.pid),
			Protocol:  protocolToString(uint16(eventC.proto)),
			Addr:      C.GoString(addr),
			Port:      uint16(eventC.port),
			Options:   optionsToString(uint8(eventC.opts)),
			Interface: interfaceString,
			Comm:      C.GoString(&eventC.task[0]),
			MountNsID: uint64(eventC.mount_ns_id),
		}

		container := t.resolver.LookupContainerByMntns(event.MountNsID)
		if container != nil {
			event.Container = container.Name
			event.Pod = container.Podname
			event.Namespace = container.Namespace
		}

		t.eventCallback(event)
	}
}
