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

//go:build linux
// +build linux

package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/tcpconnect/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -type event tcpconnect ./bpf/tcpconnect.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs        tcpconnectObjects
	v4EnterLink link.Link
	v4ExitLink  link.Link
	v6EnterLink link.Link
	v6ExitLink  link.Link
	reader      *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.v4EnterLink = gadgets.CloseLink(t.v4EnterLink)
	t.v4ExitLink = gadgets.CloseLink(t.v4ExitLink)
	t.v6EnterLink = gadgets.CloseLink(t.v6EnterLink)
	t.v6ExitLink = gadgets.CloseLink(t.v6ExitLink)

	t.objs.Close()
}

func (t *Tracer) start() error {
	var err error
	spec, err := loadTcpconnect()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
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
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.v4EnterLink, err = link.Kprobe("tcp_v4_connect", t.objs.IgTcpcV4CoE, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	t.v4ExitLink, err = link.Kretprobe("tcp_v4_connect", t.objs.IgTcpcV4CoX, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	t.v6EnterLink, err = link.Kprobe("tcp_v6_connect", t.objs.IgTcpcV6CoE, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	t.v6ExitLink, err = link.Kretprobe("tcp_v6_connect", t.objs.IgTcpcV6CoX, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	reader, err := perf.NewReader(t.objs.tcpconnectMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}
	t.reader = reader

	go t.run()

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

		bpfEvent := (*tcpconnectEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			MountNsID: bpfEvent.MntnsId,
			Pid:       bpfEvent.Pid,
			UID:       bpfEvent.Uid,
			Comm:      gadgets.FromCString(bpfEvent.Task[:]),
			Dport:     gadgets.Htons(bpfEvent.Dport),
		}

		if bpfEvent.Af == unix.AF_INET {
			event.IPVersion = 4
		} else if bpfEvent.Af == unix.AF_INET6 {
			event.IPVersion = 6
		}

		event.Saddr = gadgets.IPStringFromBytes(bpfEvent.SaddrV6, event.IPVersion)
		event.Daddr = gadgets.IPStringFromBytes(bpfEvent.DaddrV6, event.IPVersion)

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Start() error {
	if err := t.start(); err != nil {
		t.Stop()
		return err
	}
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

func (g *Gadget) NewInstance(runner gadgets.Runner) (gadgets.GadgetInstance, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
