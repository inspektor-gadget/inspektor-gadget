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
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnlat/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -type event tcpconnlat ./bpf/tcpconnlat.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
	minLatency time.Duration
}

type Tracer struct {
	config        *Config
	eventCallback func(*types.Event)

	objs   tcpconnlatObjects
	links  []link.Link
	reader *perf.Reader
}

func (t *Tracer) close() {
	for _, link := range t.links {
		gadgets.CloseLink(link)
	}
	t.links = nil
	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	var l link.Link

	spec, err := loadTcpconnlat()
	if err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
		"targ_min_ns":      t.config.minLatency,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	l, err = link.Kprobe("tcp_v4_connect", t.objs.IgTcpcV4CoE, nil)
	if err != nil {
		return fmt.Errorf("attaching program: %w", err)
	}
	t.links = append(t.links, l)

	l, err = link.Kprobe("tcp_v6_connect", t.objs.IgTcpcV6CoE, nil)
	if err != nil {
		return fmt.Errorf("attaching program: %w", err)
	}
	t.links = append(t.links, l)

	l, err = link.Kprobe("tcp_rcv_state_process", t.objs.IgTcpRsp, nil)
	if err != nil {
		return fmt.Errorf("attaching program: %w", err)
	}
	t.links = append(t.links, l)

	l, err = link.Kprobe("tcp_v4_destroy_sock", t.objs.IgTcp4Destroy, nil)
	if err != nil {
		return fmt.Errorf("attaching program: %w", err)
	}
	t.links = append(t.links, l)

	l, err = link.Kprobe("tcp_v6_destroy_sock", t.objs.IgTcp6Destroy, nil)
	if err != nil {
		return fmt.Errorf("attaching program: %w", err)
	}
	t.links = append(t.links, l)

	reader, err := perf.NewReader(t.objs.tcpconnlatMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*tcpconnlatEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:           bpfEvent.Tgid,
			Tid:           bpfEvent.Pid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Dport:         gadgets.Htons(bpfEvent.Dport),
			Sport:         bpfEvent.Lport,
			Latency:       time.Duration(int64(bpfEvent.Delta)),
		}

		if bpfEvent.Af == unix.AF_INET {
			event.IPVersion = 4
		} else if bpfEvent.Af == unix.AF_INET6 {
			event.IPVersion = 6
		}

		event.Saddr = gadgets.IPStringFromBytes(bpfEvent.SaddrV6, event.IPVersion)
		event.Daddr = gadgets.IPStringFromBytes(bpfEvent.DaddrV6, event.IPVersion)

		t.eventCallback(&event)
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.minLatency = params.Get(ParamMin).AsDuration()

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
