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
	"context"
	"fmt"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	log "github.com/sirupsen/logrus"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_t dns ./bpf/dns.c -- $CLANG_OS_FLAGS -I./bpf/ -I../../../internal/socketenricher/bpf"

const (
	BPFProgName     = "ig_trace_dns"
	BPFPerfMapName  = "events"
	BPFSocketAttach = 50
	MaxAddrAnswers  = 8 // Keep aligned with MAX_ADDR_ANSWERS in bpf/dns-common.h
)

type Tracer struct {
	*networktracer.Tracer[types.Event]

	ctx    context.Context
	cancel context.CancelFunc
	logger logger.Logger
}

func NewTracer() (*Tracer, error) {
	t := &Tracer{logger: log.StandardLogger()}

	if err := t.install(); err != nil {
		t.Close()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return t, nil
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

// List taken from:
// https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#dns-parameters-4
var qTypeNames = map[uint]string{
	1:     "A",
	2:     "NS",
	3:     "MD",
	4:     "MF",
	5:     "CNAME",
	6:     "SOA",
	7:     "MB",
	8:     "MG",
	9:     "MR",
	10:    "NULL",
	11:    "WKS",
	12:    "PTR",
	13:    "HINFO",
	14:    "MINFO",
	15:    "MX",
	16:    "TXT",
	17:    "RP",
	18:    "AFSDB",
	19:    "X25",
	20:    "ISDN",
	21:    "RT",
	22:    "NSAP",
	23:    "NSAP-PTR",
	24:    "SIG",
	25:    "KEY",
	26:    "PX",
	27:    "GPOS",
	28:    "AAAA",
	29:    "LOC",
	30:    "NXT",
	31:    "EID",
	32:    "NIMLOC",
	33:    "SRV",
	34:    "ATMA",
	35:    "NAPTR",
	36:    "KX",
	37:    "CERT",
	38:    "A6",
	39:    "DNAME",
	40:    "SINK",
	41:    "OPT",
	42:    "APL",
	43:    "DS",
	44:    "SSHFP",
	45:    "IPSECKEY",
	46:    "RRSIG",
	47:    "NSEC",
	48:    "DNSKEY",
	49:    "DHCID",
	50:    "NSEC3",
	51:    "NSEC3PARAM",
	52:    "TLSA",
	53:    "SMIMEA",
	55:    "HIP",
	56:    "NINFO",
	57:    "RKEY",
	58:    "TALINK",
	59:    "CDS",
	60:    "CDNSKEY",
	61:    "OPENPGPKEY",
	62:    "CSYNC",
	63:    "ZONEMD",
	64:    "SVCB",
	65:    "HTTPS",
	99:    "SPF",
	100:   "UINFO",
	101:   "UID",
	102:   "GID",
	103:   "UNSPEC",
	104:   "NID",
	105:   "L32",
	106:   "L64",
	107:   "LP",
	108:   "EUI48",
	109:   "EUI64",
	249:   "TKEY",
	250:   "TSIG",
	251:   "IXFR",
	252:   "AXFR",
	253:   "MAILB",
	254:   "MAILA",
	255:   "*",
	256:   "URI",
	257:   "CAA",
	258:   "AVC",
	259:   "DOA",
	260:   "AMTRELAY",
	32768: "TA",
	32769: "DLV",
}

const MaxDNSName = int(unsafe.Sizeof(dnsEventT{}.Name))

// DNS header RCODE (response code) field.
// https://datatracker.ietf.org/doc/rfc1035#section-4.1.1
var rCodeNames = map[uint8]string{
	0: "NoError",
	1: "FormErr",
	2: "ServFail",
	3: "NXDomain",
	4: "NotImp",
	5: "Refused",
}

// parseLabelSequence parses a label sequence into a string with dots.
// See https://datatracker.ietf.org/doc/html/rfc1035#section-4.1.2
func parseLabelSequence(sample []byte) (ret string) {
	sampleBounded := make([]byte, MaxDNSName)
	copy(sampleBounded, sample)

	for i := 0; i < MaxDNSName; i++ {
		length := int(sampleBounded[i])
		if length == 0 {
			break
		}
		if i+1+length < MaxDNSName {
			ret += string(sampleBounded[i+1:i+1+length]) + "."
		}
		i += length
	}
	return ret
}

func bpfEventToDNSEvent(bpfEvent *dnsEventT, netns uint64) (*types.Event, error) {
	event := types.Event{
		Event: eventtypes.Event{
			Type: eventtypes.NORMAL,
		},

		Pid:           bpfEvent.Pid,
		Tid:           bpfEvent.Tid,
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
		WithNetNsID:   eventtypes.WithNetNsID{NetNsID: netns},
		Comm:          gadgets.FromCString(bpfEvent.Task[:]),
	}
	event.Event.Timestamp = gadgets.WallTimeFromBootTime(bpfEvent.Timestamp)

	event.ID = fmt.Sprintf("%.4x", bpfEvent.Id)

	if bpfEvent.Qr == 1 {
		event.Qr = types.DNSPktTypeResponse
		if bpfEvent.Af == syscall.AF_INET {
			event.Nameserver = gadgets.IPStringFromBytes(bpfEvent.SaddrV6, 4)
		} else if bpfEvent.Af == syscall.AF_INET6 {
			event.Nameserver = gadgets.IPStringFromBytes(bpfEvent.SaddrV6, 6)
		}
	} else {
		event.Qr = types.DNSPktTypeQuery
		if bpfEvent.Af == syscall.AF_INET {
			event.Nameserver = gadgets.IPStringFromBytes(bpfEvent.DaddrV6, 4)
		} else if bpfEvent.Af == syscall.AF_INET6 {
			event.Nameserver = gadgets.IPStringFromBytes(bpfEvent.DaddrV6, 6)
		}
	}

	// Convert name into a string with dots
	event.DNSName = parseLabelSequence(bpfEvent.Name[:])

	// Parse the packet type
	event.PktType = "UNKNOWN"
	pktTypeUint := uint(bpfEvent.PktType)
	if pktTypeUint < uint(len(pktTypeNames)) {
		event.PktType = pktTypeNames[pktTypeUint]
	}

	qTypeUint := uint(bpfEvent.Qtype)
	var ok bool
	event.QType, ok = qTypeNames[qTypeUint]
	if !ok {
		event.QType = "UNASSIGNED"
	}

	if bpfEvent.Qr == 1 {
		rCodeUint := uint8(bpfEvent.Rcode)
		event.Rcode, ok = rCodeNames[rCodeUint]
		if !ok {
			event.Rcode = "UNKNOWN"
		}
	}

	// There's a limit on the number of addresses in the BPF event,
	// so bpfEvent.AnaddrCount is always less than or equal to bpfEvent.Ancount
	event.NumAnswers = int(bpfEvent.Ancount)
	for i := uint16(0); i < bpfEvent.Anaddrcount; i++ {
		// For A records, the address in the bpf event will be
		// IPv4-mapped-IPv6, which netip.Addr.Unmap() converts back to IPv4.
		addr := netip.AddrFrom16(bpfEvent.Anaddr[i]).Unmap().String()
		event.Addresses = append(event.Addresses, addr)
	}

	return &event, nil
}

// --- Registry changes

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	t.logger = gadgetCtx.Logger()
	if err := t.install(); err != nil {
		t.Close()
		return fmt.Errorf("installing tracer: %w", err)
	}

	t.ctx, t.cancel = gadgetcontext.WithTimeoutOrCancel(gadgetCtx.Context(), gadgetCtx.Timeout())
	return nil
}

func (t *Tracer) install() error {
	spec, err := loadDns()
	if err != nil {
		return fmt.Errorf("failed to load asset: %w", err)
	}

	latencyCalc, err := newDNSLatencyCalculator()
	if err != nil {
		return err
	}

	parseAndEnrichDNSEvent := func(rawSample []byte, netns uint64) (*types.Event, error) {
		bpfEvent := (*dnsEventT)(unsafe.Pointer(&rawSample[0]))
		// TODO: Why do I need 4+?
		expected := 4 + int(unsafe.Sizeof(*bpfEvent)) - MaxAddrAnswers*16 + int(bpfEvent.Anaddrcount)*16
		if len(rawSample) != expected {
			return nil, fmt.Errorf("invalid sample size: received: %d vs expected: %d",
				len(rawSample), expected)
		}

		event, err := bpfEventToDNSEvent(bpfEvent, netns)
		if err != nil {
			return nil, err
		}

		// Derive latency from the query/response timestamps.
		// Filter by packet type (OUTGOING for queries and HOST for responses) to exclude cases where
		// the packet is forwarded between containers in the host netns.
		if bpfEvent.Qr == 0 && bpfEvent.PktType == unix.PACKET_OUTGOING {
			latencyCalc.storeDNSQueryTimestamp(netns, bpfEvent.Id, uint64(event.Event.Timestamp))
		} else if bpfEvent.Qr == 1 && bpfEvent.PktType == unix.PACKET_HOST {
			event.Latency = latencyCalc.calculateDNSResponseLatency(netns, bpfEvent.Id, uint64(event.Event.Timestamp))
		}

		return event, nil
	}

	networkTracer, err := networktracer.NewTracer(
		spec,
		BPFProgName,
		BPFPerfMapName,
		BPFSocketAttach,
		types.Base,
		parseAndEnrichDNSEvent,
	)
	if err != nil {
		return fmt.Errorf("creating network tracer: %w", err)
	}
	t.Tracer = networkTracer
	return nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	<-t.ctx.Done()
	return nil
}

func (t *Tracer) Close() {
	if t.cancel != nil {
		t.cancel()
	}

	t.Tracer.Close()
}
