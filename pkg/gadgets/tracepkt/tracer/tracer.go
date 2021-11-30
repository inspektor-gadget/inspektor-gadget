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
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	"github.com/coreos/go-iptables/iptables"
	tracepkttypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/tracepkt/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

// #include "bpf/tracepkt.h"
import "C"

const (
	BPF_PROG_NAME = "kprobe_nf_log_trace"
	BPF_MAP_NAME  = "events"
)

type Tracer struct {
	collection *ebpf.Collection
	perfRd     *perf.Reader

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link

	nodeName string
	ipt      *iptables.IPTables
}

func NewTracer(nodeName string, f func(event *tracepkttypes.Event)) (*Tracer, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(ebpfProg))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %s", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %s", err)
	}

	rd, err := perf.NewReader(coll.Maps[BPF_MAP_NAME], 64*os.Getpagesize()) // 256 KB per cpu
	if err != nil {
		return nil, fmt.Errorf("failed to get a perf reader: %w", err)
	}

	ipt, err := iptables.New()
	if err != nil {
		return nil, fmt.Errorf("failed to find iptables: %w", err)
	}

	t := &Tracer{
		collection: coll,
		perfRd:     rd,
		nodeName:   nodeName,
		ipt:        ipt,
	}

	kpProg, ok := coll.Programs[BPF_PROG_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF program %q", BPF_PROG_NAME)
	}

	t.progLink, err = link.Kprobe("nf_log_trace", kpProg)
	if err != nil {
		return nil, fmt.Errorf("failed to open kprobe: %s", err)
	}

	go t.listen(rd, f)

	return t, nil
}

func parseString(rawSample []byte, offset int, sz int) string {
	out := make([]byte, sz)
	copy(out, rawSample[offset:])
	end := bytes.Index(out, []byte{0})
	if end != -1 {
		out = out[:end]
	}
	return string(out)
}

func (t *Tracer) parseEvent(rawSample []byte) *tracepkttypes.Event {
	var dummy C.struct_event_t
	if len(rawSample) < int(unsafe.Sizeof(dummy)) {
		fmt.Printf("len rawSample: %d, len struct_event_t: %d\n", len(rawSample), int(unsafe.Sizeof(dummy)))
		return nil
	}

	ifnameIn := parseString(rawSample, 0, C.IFNAMSIZ)
	ifnameOut := parseString(rawSample, C.IFNAMSIZ, C.IFNAMSIZ)
	tableName := parseString(rawSample, C.IFNAMSIZ*2, C.TABLENAMESIZ)
	chainName := parseString(rawSample, C.IFNAMSIZ*2+C.TABLENAMESIZ, C.CHAINNAMESIZ)
	comment := parseString(rawSample, C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ, C.COMMENTSIZ)

	netnsIn := binary.LittleEndian.Uint64(rawSample[C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ : C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8])
	netnsOut := binary.LittleEndian.Uint64(rawSample[C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8 : C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*2])
	rulenum := binary.LittleEndian.Uint32(rawSample[C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*2 : C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*3])

	ifindexIn := binary.LittleEndian.Uint32(rawSample[C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*3 : C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*3+4*1])
	ifindexOut := binary.LittleEndian.Uint32(rawSample[C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*3+4*1 : C.IFNAMSIZ*2+C.TABLENAMESIZ+C.CHAINNAMESIZ+C.COMMENTSIZ+8*3+4*2])

	event := &tracepkttypes.Event{
		Event: eventtypes.Event{
			Node: t.nodeName,
		},
		InterfaceNameIn:   ifnameIn,
		InterfaceNameOut:  ifnameOut,
		InterfaceIndexIn:  int(ifindexIn),
		InterfaceIndexOut: int(ifindexOut),
		NetnsIn:           netnsIn,
		NetnsOut:          netnsOut,
		TableName:         tableName,
		ChainName:         chainName,
		Comment:           comment,
		RuleNum:           int(rulenum),
	}
	return event
}

func (t *Tracer) EnrichEvent(event *tracepkttypes.Event) {
	rules, err := t.ipt.List(event.TableName, event.ChainName)
	if err != nil {
		event.Rule = err.Error()
	} else {
		event.Rules = strings.Join(rules, "\n")
		if event.RuleNum < 1 {
			event.Rule = fmt.Sprintf("invalid rule num %d in %s %s", event.RuleNum, event.TableName, event.ChainName)
		} else if int(event.RuleNum) == len(rules) {
			event.Rule = rules[0]
		} else if int(event.RuleNum) < len(rules) {
			event.Rule = rules[event.RuleNum]
		}
	}
}

func (t *Tracer) listen(rd *perf.Reader, f func(event *tracepkttypes.Event)) {
	for {
		record, err := rd.Read()
		if err != nil {
			if perf.IsClosed(err) {
				return
			}
			log.Errorf("Error while reading from perf event reader: %s", err)
			return
		}

		if record.LostSamples != 0 {
			log.Warnf("Warning: perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}

		event := t.parseEvent(record.RawSample)
		if event == nil {
			log.Warnf("Warning: could not parse sample from perf event ring buffer")
			continue
		}

		f(event)
	}

}

func (t *Tracer) Close() {
	t.perfRd.Close()
	t.progLink.Close()
	t.collection.Close()
}
