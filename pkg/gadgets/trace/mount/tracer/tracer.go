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
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags ${CFLAGS} -type event -type op mountsnoop ./bpf/mountsnoop.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs            mountsnoopObjects
	mountEnterLink  link.Link
	umountEnterLink link.Link
	mountExitLink   link.Link
	umountExitLink  link.Link
	reader          *perf.Reader
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
	t.mountEnterLink = gadgets.CloseLink(t.mountEnterLink)
	t.umountEnterLink = gadgets.CloseLink(t.umountEnterLink)
	t.mountExitLink = gadgets.CloseLink(t.mountExitLink)
	t.umountExitLink = gadgets.CloseLink(t.umountExitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error
	spec, err := loadMountsnoop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.mountEnterLink, err = link.Tracepoint("syscalls", "sys_enter_mount", t.objs.IgMountE, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.mountExitLink, err = link.Tracepoint("syscalls", "sys_exit_mount", t.objs.IgMountX, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.umountEnterLink, err = link.Tracepoint("syscalls", "sys_enter_umount", t.objs.IgUmountE, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.umountExitLink, err = link.Tracepoint("syscalls", "sys_exit_umount", t.objs.IgUmountX, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

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

		bpfEvent := (*mountsnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MountNsId},
			Pid:           bpfEvent.Pid,
			Tid:           bpfEvent.Tid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Retval:        int(bpfEvent.Ret),
			Latency:       bpfEvent.Delta,
			Fs:            gadgets.FromCString(bpfEvent.Fs[:]),
			Source:        gadgets.FromCString(bpfEvent.Src[:]),
			Target:        gadgets.FromCString(bpfEvent.Dest[:]),
			Data:          gadgets.FromCString(bpfEvent.Data[:]),
		}

		switch bpfEvent.Op {
		case mountsnoopOpMOUNT:
			event.Operation = "mount"
		case mountsnoopOpUMOUNT:
			event.Operation = "umount"
		default:
			event.Operation = "unknown"
		}

		event.Flags = DecodeFlags(bpfEvent.Flags)

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
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
