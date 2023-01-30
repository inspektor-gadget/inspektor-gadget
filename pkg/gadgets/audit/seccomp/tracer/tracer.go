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

package tracer

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/audit/seccomp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type event -cc clang auditseccomp ./bpf/audit-seccomp.bpf.c -- -I./bpf/ -I../../../../ -I../../../../${TARGET} -D__KERNEL__

type Tracer struct {
	config        *Config
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
	ContainersMap *ebpf.Map
	MountnsMap    *ebpf.Map
}

func NewTracer(config *Config, eventCallback func(*types.Event)) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		eventCallback: eventCallback,
	}

	if err := t.start(); err != nil {
		t.Close()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) start() error {
	spec, err := loadAuditseccomp()
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
	if t.config.ContainersMap != nil {
		mapReplacements["containers"] = t.config.ContainersMap
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

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", t.objs.IgAuditSecc, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}

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

		eventC := (*auditseccompEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(eventC.Timestamp),
				CommonData: eventtypes.CommonData{
					// Get 'Namespace', 'Pod' and 'Container' from
					// BPF and not from the gadget helpers  because the
					// container might be terminated immediately
					// after the BPF kprobe on audit_seccomp() is
					// executed (e.g. with SCMP_ACT_KILL), so by
					// the time the event is read from the perf
					// ring buffer, we might not be able to get the
					// Kubernetes metadata from the mount namespace
					// id.
					Namespace: gadgets.FromCString(eventC.Container.Namespace[:]),
					Pod:       gadgets.FromCString(eventC.Container.Pod[:]),
					Container: gadgets.FromCString(eventC.Container.Container[:]),
				},
			},
			Pid:       uint32(eventC.Pid),
			MountNsID: uint64(eventC.MntnsId),
			Syscall:   syscallToName(int(eventC.Syscall)),
			Code:      codeToName(uint(eventC.Code)),
			Comm:      gadgets.FromCString(eventC.Comm[:]),
		}

		t.eventCallback(&event)
	}
}

func (t *Tracer) Close() {
	t.progLink = gadgets.CloseLink(t.progLink)
	if t.reader != nil {
		t.reader.Close()
	}
	t.objs.Close()
}

// ---

func (t *Tracer) Start() error {
	var err error
	var spec *ebpf.CollectionSpec

	config := t.config

	spec, err = loadAuditseccomp()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = config.MountnsMap
	}
	if config.ContainersMap != nil {
		mapReplacements["containers"] = config.ContainersMap
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

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("failed to get a perf reader: %w", err)
	}

	t.progLink, err = link.Kprobe("audit_seccomp", t.objs.IgAuditSecc, nil)
	if err != nil {
		return fmt.Errorf("failed to attach kprobe: %w", err)
	}

	go t.run()

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetContainersMap(containersMap *ebpf.Map) {
	t.config.ContainersMap = containersMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (t *Tracer) Stop() {
}

func (g *gadget) NewInstance(runner gadgets.Runner) (gadgets.GadgetInstance, error) {
	t := &Tracer{
		config: &Config{},
	}
	return t, nil
}
