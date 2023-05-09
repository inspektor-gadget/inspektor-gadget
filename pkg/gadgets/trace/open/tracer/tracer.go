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
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	log "github.com/sirupsen/logrus"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -type event opensnoop ./bpf/opensnoop.bpf.c -- -I./bpf/ -I../../../../${TARGET} -I ../../../common/

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs            opensnoopObjects
	openEnterLink   link.Link
	openAtEnterLink link.Link
	openExitLink    link.Link
	openAtExitLink  link.Link
	reader          *perf.Reader
	logger          logger.Logger
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
		logger:        log.StandardLogger(),
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
	t.openEnterLink = gadgets.CloseLink(t.openEnterLink)
	t.openAtEnterLink = gadgets.CloseLink(t.openAtEnterLink)
	t.openExitLink = gadgets.CloseLink(t.openExitLink)
	t.openAtExitLink = gadgets.CloseLink(t.openAtExitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadOpensnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs, t.logger); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	// arm64 does not defined an open() syscall, only openat().
	if runtime.GOARCH != "arm64" {
		openEnter, err := link.Tracepoint("syscalls", "sys_enter_open", t.objs.IgOpenE, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint: %w", err)
		}
		t.openEnterLink = openEnter
	}

	openAtEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", t.objs.IgOpenatE, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openAtEnterLink = openAtEnter

	if runtime.GOARCH != "arm64" {
		openExit, err := link.Tracepoint("syscalls", "sys_exit_open", t.objs.IgOpenX, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint: %w", err)
		}
		t.openExitLink = openExit
	}

	openAtExit, err := link.Tracepoint("syscalls", "sys_exit_openat", t.objs.IgOpenatX, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openAtExitLink = openAtExit

	reader, err := perf.NewReader(t.objs.opensnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
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

		bpfEvent := (*opensnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		ret := int(bpfEvent.Ret)
		fd := 0
		errval := 0

		if ret >= 0 {
			fd = ret
		} else {
			errval = -ret
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:           bpfEvent.Pid,
			Uid:           bpfEvent.Uid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Ret:           ret,
			Fd:            fd,
			Err:           errval,
			Path:          gadgets.FromCString(bpfEvent.Fname[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.logger = gadgetCtx.Logger()
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
