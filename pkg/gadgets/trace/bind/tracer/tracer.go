// Copyright 2019-2023 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/vishvananda/netlink"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/bind/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/nsenter"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -type bind_event bindsnoop ./bpf/bindsnoop.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap   *ebpf.Map
	TargetPid    int32
	TargetPorts  []uint16
	IgnoreErrors bool
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs      bindsnoopObjects
	ipv4Entry link.Link
	ipv4Exit  link.Link
	ipv6Entry link.Link
	ipv6Exit  link.Link
	reader    *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	t.ipv4Entry = gadgets.CloseLink(t.ipv4Entry)
	t.ipv4Exit = gadgets.CloseLink(t.ipv4Exit)
	t.ipv6Entry = gadgets.CloseLink(t.ipv6Entry)
	t.ipv6Exit = gadgets.CloseLink(t.ipv6Exit)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadBindsnoop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
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
		"target_pid":     t.config.TargetPid,
		"filter_by_port": filterByPort,
		"ignore_errors":  t.config.IgnoreErrors,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.ipv4Entry, err = link.Kprobe("inet_bind", t.objs.IgBindIpv4E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kprobe: %w", err)
	}

	t.ipv4Exit, err = link.Kretprobe("inet_bind", t.objs.IgBindIpv4X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv4 kprobe: %w", err)
	}

	t.ipv6Entry, err = link.Kprobe("inet6_bind", t.objs.IgBindIpv6E, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kprobe: %w", err)
	}

	t.ipv6Exit, err = link.Kretprobe("inet6_bind", t.objs.IgBindIpv6X, nil)
	if err != nil {
		return fmt.Errorf("attaching ipv6 kprobe: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	if err := gadgets.FreezeMaps(t.objs.Events); err != nil {
		return err
	}

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

			msg := fmt.Sprintf("reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*bindsnoopBindEvent)(unsafe.Pointer(&record.RawSample[0]))

		addr := gadgets.IPStringFromBytes(bpfEvent.Addr, int(bpfEvent.Ver))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			Pid:           bpfEvent.Pid,
			Protocol:      protocolToString(bpfEvent.Proto),
			Addr:          addr,
			Port:          bpfEvent.Port,
			Options:       optionsToString(bpfEvent.Opts),
			Comm:          gadgets.FromCString(bpfEvent.Task[:]),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		interfaceString := ""

		interfaceNum := int(bpfEvent.BoundDevIf)
		if interfaceNum != 0 {
			// It does exist a net link which index is 0.
			// But eBPF bindsnoop code often gives 0 as interface number:
			// https://github.com/iovisor/bcc/blob/63618552f81a2631990eff59fd7460802c58c30b/tools/bindsnoop_example.txt#L16
			// So, we only use this function if interface number is different than 0.

			var interf netlink.Link
			pid := int(event.Pid)

			// Current limitations:
			// - Short-lived processed might have terminated already, so we cannot enter
			//   its netns.
			// - 'pid' is from the top-level pid namespace, which might differ from IG's
			//   /host/proc/ on some setups such as Minikube with the docker driver.

			err := nsenter.NetnsEnter(pid, func() error {
				interf, err = netlink.LinkByIndex(interfaceNum)
				if err != nil {
					return err
				}
				return nil
			})
			if err != nil {
				msg := fmt.Sprintf("Cannot find interface name for index : %d (PID : %d) : %s", interfaceNum, pid, err)
				t.eventCallback(types.Base(eventtypes.Err(msg)))
				continue
			}

			if interf != nil {
				interfaceString = interf.Attrs().Name
			}

		}
		event.Interface = interfaceString

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.TargetPid = params.Get(ParamPID).AsInt32()
	t.config.TargetPorts = params.Get(ParamPorts).AsUint16Slice()
	t.config.IgnoreErrors = params.Get(ParamIgnoreErrors).AsBool()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	// TODO: Rework this to be able to stop the gadget when an error occurs in
	// run(). Notice it is the same for most of gadgets in the trace category.
	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
