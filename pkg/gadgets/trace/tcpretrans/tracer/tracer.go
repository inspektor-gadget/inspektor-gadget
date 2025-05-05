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
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpretrans/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tcpbits"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types -type event -type type tcpretrans ./bpf/tcpretrans.bpf.c -- -I./bpf/

type Tracer struct {
	socketEnricherMap *ebpf.Map

	eventCallback func(*types.Event)

	objs              tcpretransObjects
	retransmitSkbLink link.Link
	lossSkbLink       link.Link
	reader            *perf.Reader
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
	t.retransmitSkbLink = gadgets.CloseLink(t.retransmitSkbLink)
	t.lossSkbLink = gadgets.CloseLink(t.lossSkbLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error

	spec, err := loadTcpretrans()
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

	t.retransmitSkbLink, err = link.Tracepoint("tcp", "tcp_retransmit_skb", t.objs.IgTcpretrans, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint tcp_retransmit_skb: %w", err)
	}

	t.lossSkbLink, err = link.Kprobe("tcp_send_loss_probe", t.objs.IgTcplossprobe, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe tcp_send_loss_probe: %w", err)
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

		bpfEvent := (*tcpretransEvent)(unsafe.Pointer(&record.RawSample[0]))

		ipversion := gadgets.IPVerFromAF(bpfEvent.Af)

		typ := "unknown"
		switch bpfEvent.Type {
		case tcpretransTypeRETRANS:
			typ = "RETRANS"
		case tcpretransTypeLOSS:
			typ = "LOSS"
		}

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
			IPVersion:     ipversion,
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
			State:    tcpbits.TCPState(bpfEvent.State),
			Tcpflags: tcpbits.TCPFlags(bpfEvent.Tcpflags),
			Type:     typ,
		}

		t.eventCallback(&event)
	}
}
