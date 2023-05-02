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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type event -cc clang auditseccomp ./bpf/audit-seccomp.bpf.c -- -I./bpf/ -I../../../../ -I../../../../${TARGET} -D__KERNEL__ -I ../../../common/

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs   auditseccompObjects
	reader *perf.Reader

	// progLink links the BPF program to the tracepoint.
	// A reference is kept so it can be closed it explicitly, otherwise
	// the garbage collector might unlink it via the finalizer at any
	// moment.
	progLink link.Link
}

type Config struct {
	MountnsMap *ebpf.Map
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
		t.Close()
		return nil, err
	}

	go t.run()

	return t, nil
}

func (t *Tracer) install() error {
	spec, err := loadAuditseccomp()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements[gadgets.MntNsFilterMapName] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		gadgets.FilterByMntNsName: filterByMntNs,
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

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", t.objs.IgAuditSecc, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
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

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		eventC := (*auditseccompEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(eventC.Timestamp),
			},
			Pid:           uint32(eventC.Pid),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: eventC.MntnsId},
			Syscall:       syscallToName(int(eventC.Syscall)),
			Code:          codeToName(uint(eventC.Code)),
			Comm:          gadgets.FromCString(eventC.Comm[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// Close closes the tracer
// TODO: Unexport this function when the refactoring is done
func (t *Tracer) Close() {
	t.progLink = gadgets.CloseLink(t.progLink)
	if t.reader != nil {
		t.reader.Close()
	}
	t.objs.Close()
}

// ---

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.Close()
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
	t := &Tracer{
		config: &Config{},
	}
	return t, nil
}
