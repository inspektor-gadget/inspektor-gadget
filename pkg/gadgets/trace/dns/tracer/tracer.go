// Copyright 2019-2024 The Inspektor Gadget authors
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
	"context"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	log "github.com/sirupsen/logrus"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/networktracer"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type event_t dns ./bpf/dns.c -- $CLANG_OS_FLAGS -I./bpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type event_t dnsWithLongPaths ./bpf/dns.c -- -DWITH_LONG_PATHS $CLANG_OS_FLAGS -I./bpf/

// Keep in sync with values in bpf/dns.c
const (
	BPFQueryMapName = "query_map"
	maxPorts        = 16
)

type Config struct {
	DnsTimeout time.Duration
	Ports      []uint16
	GetPaths   bool
}

type Tracer struct {
	*networktracer.Tracer[types.Event]

	config *Config

	ctx    context.Context
	cancel context.CancelFunc
}

func NewTracer(config *Config) (*Tracer, error) {
	t := &Tracer{
		config: config,
	}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
}

// RunWorkaround is used by pkg/gadget-collection/gadgets/trace/dns/gadget.go to run the gadget
// after calling NewTracer()
func (t *Tracer) RunWorkaround() error {
	// timeout nor ports configurable in this case
	t.config.DnsTimeout = time.Minute
	t.config.Ports = []uint16{53, 5353}
	if err := t.run(context.TODO(), log.StandardLogger()); err != nil {
		t.Close()
		return fmt.Errorf("running tracer: %w", err)
	}
	return nil
}

// pkt_type definitions:
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

func pktTypeToString(pktType uint8) string {
	pktTypeUint := uint(pktType)
	if pktTypeUint < uint(len(pktTypeNames)) {
		return pktTypeNames[pktType]
	}

	return "UNKNOWN"
}

// --- Registry changes

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{
		config: &Config{},
	}, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	if err := t.install(); err != nil {
		t.Close()
		return fmt.Errorf("installing tracer: %w", err)
	}

	t.ctx, t.cancel = gadgetcontext.WithTimeoutOrCancel(gadgetCtx.Context(), gadgetCtx.Timeout())

	return nil
}

func (t *Tracer) install() error {
	networkTracer, err := networktracer.NewTracer[types.Event]()
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}
	t.Tracer = networkTracer
	return nil
}

func (t *Tracer) parseDNSPacket(rawSample []byte, netns uint64) (*types.Event, error) {
	// The sample received is a concatenation of the dnsEventT structure and the packet bytes.
	bpfEvent := (*dnsEventT)(unsafe.Pointer(&rawSample[0]))
	bpfEventWithLongPaths := (*dnsWithLongPathsEventT)(unsafe.Pointer(&rawSample[0]))

	structSize := unsafe.Sizeof(*bpfEvent)
	if t.config.GetPaths {
		structSize = unsafe.Sizeof(*bpfEventWithLongPaths)
	}
	if len(rawSample) < int(structSize) {
		return nil, fmt.Errorf("event too short")
	}
	packetBytes := rawSample[structSize:]
	if len(packetBytes) < int(bpfEvent.DnsOff) {
		return nil, fmt.Errorf("packet too short")
	}

	dnsLayer := layers.DNS{}
	err := dnsLayer.DecodeFromBytes(packetBytes[bpfEvent.DnsOff:], gopacket.NilDecodeFeedback)
	if err != nil {
		return nil, fmt.Errorf("decoding dns layer: %w", err)
	}

	ipversion := gadgets.IPVerFromAF(bpfEvent.Af)

	event := &types.Event{
		Event: eventtypes.Event{
			Type:      eventtypes.NORMAL,
			Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
		},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		Ppid:          bpfEvent.Ppid,
		Uid:           bpfEvent.Uid,
		Gid:           bpfEvent.Gid,
		Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
		Pcomm:         gadgets.FromCString(bpfEvent.Pcomm[:]),
		PktType:       pktTypeToString(bpfEvent.PktType),

		SrcIP:    gadgets.IPStringFromBytes(bpfEvent.SaddrV6, ipversion),
		DstIP:    gadgets.IPStringFromBytes(bpfEvent.DaddrV6, ipversion),
		SrcPort:  bpfEvent.Sport,
		DstPort:  bpfEvent.Dport,
		Protocol: gadgets.ProtoString(int(bpfEvent.Proto)),

		ID:         fmt.Sprintf("%.4x", dnsLayer.ID),
		NumAnswers: int(dnsLayer.ANCount),
	}
	if t.config.GetPaths {
		event.Cwd = gadgets.FromCString(bpfEventWithLongPaths.Cwd[:])
		event.Exepath = gadgets.FromCString(bpfEventWithLongPaths.Exepath[:])
	}

	if dnsLayer.QR {
		event.Qr = types.DNSPktTypeResponse
		event.Nameserver = event.SrcIP

		event.Latency = time.Duration(bpfEvent.LatencyNs)
		event.Rcode = dnsLayer.ResponseCode.String()
	} else {
		event.Qr = types.DNSPktTypeQuery
		event.Nameserver = event.DstIP
	}

	if len(dnsLayer.Questions) > 0 {
		question := dnsLayer.Questions[0]
		event.QType = question.Type.String()
		event.DNSName = string(question.Name) + "."
	}

	for _, answer := range dnsLayer.Answers {
		if answer.IP == nil {
			continue
		}

		event.Addresses = append(event.Addresses, answer.IP.String())
	}

	return event, nil
}

func (t *Tracer) run(ctx context.Context, logger logger.Logger) error {
	var spec *ebpf.CollectionSpec
	var err error

	if t.config.GetPaths {
		spec, err = loadDnsWithLongPaths()
	} else {
		spec, err = loadDns()
	}
	if err != nil {
		return fmt.Errorf("loading asset: %w", err)
	}

	if len(t.config.Ports) > maxPorts {
		return fmt.Errorf("too many ports specified, max is %d", maxPorts)
	}

	portsArray := [maxPorts]uint16{0}
	copy(portsArray[:], t.config.Ports)

	dnsSpec := &dnsSpecs{}
	if err := spec.Assign(dnsSpec); err != nil {
		return err
	}

	constants := map[*ebpf.VariableSpec]any{
		dnsSpec.Ports:    portsArray,
		dnsSpec.PortsLen: uint16(len(t.config.Ports)),
	}
	for varSpec, val := range constants {
		if err := varSpec.Set(val); err != nil {
			return fmt.Errorf("setting variable %s: %w", varSpec, err)
		}
	}

	if err := t.Tracer.Run(spec, types.Base, t.parseDNSPacket); err != nil {
		return fmt.Errorf("setting network tracer spec: %w", err)
	}

	// Start a background thread to garbage collect queries without responses
	// from the queries map (used to calculate DNS latency).
	// The goroutine terminates when t.ctx is done.
	queryMap := t.GetMap(BPFQueryMapName)
	if queryMap == nil {
		t.Close()
		return fmt.Errorf("got nil retrieving DNS query map")
	}
	startGarbageCollector(ctx, logger, t.config.DnsTimeout, queryMap)

	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.config.DnsTimeout = gadgetCtx.GadgetParams().Get(ParamDNSTimeout).AsDuration()
	t.config.Ports = gadgetCtx.GadgetParams().Get(ParamPorts).AsUint16Slice()
	t.config.GetPaths = gadgetCtx.GadgetParams().Get(ParamPaths).AsBool()

	if err := t.run(t.ctx, gadgetCtx.Logger()); err != nil {
		return err
	}

	<-t.ctx.Done()
	return nil
}

func (t *Tracer) Close() {
	if t.cancel != nil {
		t.cancel()
	}

	if t.Tracer != nil {
		t.Tracer.Close()
	}
}
