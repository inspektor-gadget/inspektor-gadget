// Copyright 2022-2023 The Inspektor Gadget authors
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
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -type event tcpconnect ./bpf/tcpconnect.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap       *ebpf.Map
	CalculateLatency bool
	MinLatency       time.Duration
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs                   tcpconnectObjects
	v4EnterLink            link.Link
	v4ExitLink             link.Link
	v6EnterLink            link.Link
	v6ExitLink             link.Link
	tcpDestroySockLink     link.Link
	tcpRvcStateProcessLink link.Link
	reader                 *perf.Reader
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
	t.v4EnterLink = gadgets.CloseLink(t.v4EnterLink)
	t.v4ExitLink = gadgets.CloseLink(t.v4ExitLink)
	t.v6EnterLink = gadgets.CloseLink(t.v6EnterLink)
	t.v6ExitLink = gadgets.CloseLink(t.v6ExitLink)
	t.tcpDestroySockLink = gadgets.CloseLink(t.tcpDestroySockLink)
	t.tcpRvcStateProcessLink = gadgets.CloseLink(t.tcpRvcStateProcessLink)

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	spec, err := loadTcpconnect()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"targ_min_latency_ns": t.config.MinLatency,
		"calculate_latency":   t.config.CalculateLatency,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.v4EnterLink, err = link.Kprobe("tcp_v4_connect", t.objs.IgTcpcV4CoE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}

	t.v6EnterLink, err = link.Kprobe("tcp_v6_connect", t.objs.IgTcpcV6CoE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}

	if !t.config.CalculateLatency {
		t.v4ExitLink, err = link.Kretprobe("tcp_v4_connect", t.objs.IgTcpcV4CoX, nil)
		if err != nil {
			return fmt.Errorf("attaching kretprobe: %w", err)
		}

		t.v6ExitLink, err = link.Kretprobe("tcp_v6_connect", t.objs.IgTcpcV6CoX, nil)
		if err != nil {
			return fmt.Errorf("attaching kretprobe: %w", err)
		}
	} else {
		t.tcpDestroySockLink, err = link.Tracepoint("tcp", "tcp_destroy_sock", t.objs.IgTcpDestroy, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint: %w", err)
		}

		t.tcpRvcStateProcessLink, err = link.Kprobe("tcp_rcv_state_process", t.objs.IgTcpRsp, nil)
		if err != nil {
			return fmt.Errorf("attaching kprobe: %w", err)
		}
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

		bpfEvent := (*tcpconnectEvent)(unsafe.Pointer(&record.RawSample[0]))

		ipversion := gadgets.IPVerFromAF(bpfEvent.Af)

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:           bpfEvent.Pid,
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			Comm:          gadgets.FromCString(bpfEvent.Task[:]),
			SrcEndpoint: eventtypes.L4Endpoint{
				L3Endpoint: eventtypes.L3Endpoint{
					Addr:    gadgets.IPStringFromBytes(bpfEvent.SaddrV6, ipversion),
					Version: uint8(ipversion),
				},
				Port: gadgets.Htons(bpfEvent.Sport),
			},
			DstEndpoint: eventtypes.L4Endpoint{
				L3Endpoint: eventtypes.L3Endpoint{
					Addr:    gadgets.IPStringFromBytes(bpfEvent.DaddrV6, ipversion),
					Version: uint8(ipversion),
				},
				Port: gadgets.Htons(bpfEvent.Dport),
			},
			IPVersion: ipversion,
			Latency:   time.Duration(int64(bpfEvent.Latency)),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.CalculateLatency = params.Get(ParamLatency).AsBool()
	t.config.MinLatency = params.Get(ParamMin).AsDuration()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

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
