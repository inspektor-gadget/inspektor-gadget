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

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/networktracer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/internal/socketenricher"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpretrans/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/tcpbits"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -no-global-types -type event tcpretrans ./bpf/tcpretrans.bpf.c -- -I./bpf/ -I../../../../${TARGET} -I../../../internal/socketenricher/bpf

type Tracer struct {
	socketEnricher *socketenricher.SocketEnricher

	eventCallback func(*types.Event)

	objs              tcpretransObjects
	retransmitSkbLink link.Link
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

func (t *Tracer) close() {
	t.retransmitSkbLink = gadgets.CloseLink(t.retransmitSkbLink)

	if t.reader != nil {
		t.reader.Close()
	}

	if t.socketEnricher != nil {
		t.socketEnricher.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	t.socketEnricher, err = socketenricher.NewSocketEnricher()
	if err != nil {
		return err
	}

	spec, err := loadTcpretrans()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	opts := ebpf.CollectionOptions{}

	mapReplacements := map[string]*ebpf.Map{}
	mapReplacements[networktracer.SocketsMapName] = t.socketEnricher.SocketsMap()
	opts.MapReplacements = mapReplacements

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	t.retransmitSkbLink, err = link.Tracepoint("tcp", "tcp_retransmit_skb", t.objs.IgTcpretrans, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint tcp_retransmit_skb: %w", err)
	}

	reader, err := perf.NewReader(t.objs.tcpretransMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	t.reader = reader

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
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*tcpretransEvent)(unsafe.Pointer(&record.RawSample[0]))

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
			IPVersion:     ipversion,
			Saddr:         gadgets.IPStringFromBytes(bpfEvent.Saddr, ipversion),
			Daddr:         gadgets.IPStringFromBytes(bpfEvent.Daddr, ipversion),
			Dport:         gadgets.Htons(bpfEvent.Dport),
			Sport:         gadgets.Htons(bpfEvent.Sport),
			State:         tcpbits.TCPState(bpfEvent.State),
			Tcpflags:      tcpbits.TCPFlags(bpfEvent.Tcpflags),
		}

		t.eventCallback(&event)
	}
}
