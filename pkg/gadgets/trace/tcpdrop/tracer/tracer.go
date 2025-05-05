// Copyright 2023 The Inspektor Gadget authors
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
	"strings"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpdrop/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tcpbits"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types -type event tcpdrop ./bpf/tcpdrop.bpf.c -- -I./bpf/
type Tracer struct {
	socketEnricherMap *ebpf.Map
	dropReasons       map[int]string

	eventCallback func(*types.Event)

	objs         tcpdropObjects
	kfreeSkbLink link.Link
	reader       *perf.Reader
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *Tracer) SetSocketEnricherMap(m *ebpf.Map) {
	t.socketEnricherMap = m
}

func (t *Tracer) close() {
	t.kfreeSkbLink = gadgets.CloseLink(t.kfreeSkbLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) loadDropReasons() error {
	btfSpec, err := btf.LoadKernelSpec()
	if err != nil {
		return fmt.Errorf("loading kernel spec: %w", err)
	}

	t.dropReasons = make(map[int]string)
	enum := &btf.Enum{}
	err = btfSpec.TypeByName("skb_drop_reason", &enum)
	if err != nil {
		return fmt.Errorf("looking up skb_drop_reason enum: %w", err)
	}
	for _, v := range enum.Values {
		str := v.Name
		str = strings.TrimPrefix(str, "SKB_DROP_REASON_")
		str = strings.TrimPrefix(str, "SKB_")

		t.dropReasons[int(v.Value)] = str
	}

	return nil
}

func (t *Tracer) install() error {
	err := t.loadDropReasons()
	if err != nil {
		return err
	}

	spec, err := loadTcpdrop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}

	mapReplacements := map[string]*ebpf.Map{}
	mapReplacements[socketenricher.SocketsMapName] = t.socketEnricherMap
	opts.MapReplacements = mapReplacements

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	t.kfreeSkbLink, err = link.Tracepoint("skb", "kfree_skb", t.objs.IgTcpdrop, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint kfree_skb: %w", err)
	}

	reader, err := perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	t.reader = reader

	if err := gadgets.FreezeMaps(t.objs.Events); err != nil {
		return err
	}

	return nil
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

		bpfEvent := (*tcpdropEvent)(unsafe.Pointer(&record.RawSample[0]))

		reason, err := t.lookupDropReason(int(bpfEvent.Reason))
		if err != nil {
			msg := fmt.Sprintf("looking up drop reason: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			continue
		}

		ipversion := gadgets.IPVerFromAF(bpfEvent.Af)

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.ProcSocket.MountNsId},
			WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(bpfEvent.Netns)},
			Pid:           bpfEvent.ProcSocket.Pid,
			Uid:           bpfEvent.ProcSocket.Uid,
			Gid:           bpfEvent.ProcSocket.Gid,
			Comm:          gadgets.FromCString(bpfEvent.ProcSocket.Task[:]),

			SrcEndpoint: eventtypes.L4Endpoint{
				L3Endpoint: eventtypes.L3Endpoint{
					Addr:    gadgets.IPStringFromBytes(bpfEvent.Saddr, ipversion),
					Version: uint8(ipversion),
				},
				Port: gadgets.Htons(bpfEvent.Sport),
			},
			DstEndpoint: eventtypes.L4Endpoint{
				L3Endpoint: eventtypes.L3Endpoint{
					Addr:    gadgets.IPStringFromBytes(bpfEvent.Daddr, ipversion),
					Version: uint8(ipversion),
				},
				Port: gadgets.Htons(bpfEvent.Dport),
			},
			State:     tcpbits.TCPState(bpfEvent.State),
			Tcpflags:  tcpbits.TCPFlags(bpfEvent.Tcpflags),
			Reason:    reason,
			IPVersion: ipversion,
		}

		t.eventCallback(&event)
	}
}

func (t *Tracer) lookupDropReason(reason int) (string, error) {
	if ret, ok := t.dropReasons[reason]; ok {
		return ret, nil
	}
	return "", fmt.Errorf("unknown drop reason: %d", reason)
}
