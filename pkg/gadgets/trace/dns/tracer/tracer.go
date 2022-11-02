// Copyright 2019-2021 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/dns/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/rawsock"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate bash -c "source ./clangosflags.sh; go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event_t dns ./bpf/dns.c -- $CLANG_OS_FLAGS -I./bpf/"

const (
	BPFProgName     = "ig_trace_dns"
	BPFMapName      = "events"
	BPFSocketAttach = 50
)

type link struct {
	collection *ebpf.Collection
	perfRd     *perf.Reader

	sockFd int

	// users count how many users called Attach(). This can happen for two reasons:
	// 1. several containers in a pod (sharing the netns)
	// 2. pods with networkHost=true
	users int
}

type Tracer struct {
	spec *ebpf.CollectionSpec

	// key: namespace/podname
	// value: Tracelet
	attachments map[string]*link
}

func NewTracer() (*Tracer, error) {
	spec, err := loadDns()
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	t := &Tracer{
		spec:        spec,
		attachments: make(map[string]*link),
	}

	return t, nil
}

func (t *Tracer) Attach(
	key string,
	pid uint32,
	eventCallback func(types.Event),
) (err error) {
	if l, ok := t.attachments[key]; ok {
		l.users++
		return nil
	}

	l := &link{
		sockFd: -1,
		users:  1,
	}
	defer func() {
		if err != nil {
			if l.perfRd != nil {
				l.perfRd.Close()
			}
			if l.sockFd != -1 {
				unix.Close(l.sockFd)
			}
			if l.collection != nil {
				l.collection.Close()
			}
		}
	}()

	l.collection, err = ebpf.NewCollection(t.spec)
	if err != nil {
		return fmt.Errorf("failed to create BPF collection: %w", err)
	}

	l.perfRd, err = perf.NewReader(l.collection.Maps[BPFMapName], gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	prog, ok := l.collection.Programs[BPFProgName]
	if !ok {
		return fmt.Errorf("failed to find BPF program %q", BPFProgName)
	}

	l.sockFd, err = rawsock.OpenRawSock(pid)
	if err != nil {
		return fmt.Errorf("failed to open raw socket: %w", err)
	}

	if err := syscall.SetsockoptInt(l.sockFd, syscall.SOL_SOCKET, BPFSocketAttach, prog.FD()); err != nil {
		return fmt.Errorf("failed to attach BPF program: %w", err)
	}

	t.attachments[key] = l

	go t.listen(key, l.perfRd, eventCallback)

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

func parseDNSEvent(rawSample []byte) (*types.Event, error) {
	event := types.Event{
		Event: eventtypes.Event{
			Type: eventtypes.NORMAL,
		},
	}

	bpfEvent := (*dnsEventT)(unsafe.Pointer(&rawSample[0]))
	if len(rawSample) < int(unsafe.Sizeof(*bpfEvent)) {
		return nil, errors.New("invalid sample size")
	}

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
	event.DNSName = parseLabelSequence(rawSample[unsafe.Offsetof(bpfEvent.Name):])

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

	return &event, nil
}

func (t *Tracer) listen(
	key string,
	rd *perf.Reader,
	eventCallback func(types.Event),
) {
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer (%s): %s", key, err)
			eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples != 0 {
			msg := fmt.Sprintf("lost %d samples (%s)", record.LostSamples, key)
			eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		event, err := parseDNSEvent(record.RawSample)
		if err != nil {
			eventCallback(types.Base(eventtypes.Err(err.Error())))
			continue
		}
		eventCallback(*event)
	}
}

func (t *Tracer) releaseLink(key string, l *link) {
	l.perfRd.Close()
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
}
