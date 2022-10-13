//go:build linux
// +build linux

// Copyright 2019-2021 The Inspektor Gadget authors
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

// #include <linux/types.h>
// #include "./bpf/mountsnoop.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/mount/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang mountsnoop ./bpf/mountsnoop.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricher
	eventCallback func(types.Event)

	objs            mountsnoopObjects
	mountEnterLink  link.Link
	umountEnterLink link.Link
	mountExitLink   link.Link
	umountExitLink  link.Link
	reader          *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricher,
	eventCallback func(types.Event),
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
	t.mountEnterLink = gadgets.CloseLink(t.mountEnterLink)
	t.umountEnterLink = gadgets.CloseLink(t.umountEnterLink)
	t.mountExitLink = gadgets.CloseLink(t.mountExitLink)
	t.umountExitLink = gadgets.CloseLink(t.umountExitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	var err error
	spec, err := loadMountsnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

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

	t.mountEnterLink, err = link.Tracepoint("syscalls", "sys_enter_mount", t.objs.IgMountE, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.mountExitLink, err = link.Tracepoint("syscalls", "sys_exit_mount", t.objs.IgMountX, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.umountEnterLink, err = link.Tracepoint("syscalls", "sys_enter_umount", t.objs.IgUmountE, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.umountExitLink, err = link.Tracepoint("syscalls", "sys_exit_umount", t.objs.IgUmountX, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.mountsnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
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

		eventC := (*C.struct_event)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			MountNsID: uint64(eventC.mount_ns_id),
			Pid:       uint32(eventC.pid),
			Tid:       uint32(eventC.tid),
			Comm:      C.GoString(&eventC.comm[0]),
			Retval:    int(eventC.ret),
			Latency:   uint64(eventC.delta),
			Fs:        C.GoString(&eventC.fs[0]),
			Source:    C.GoString(&eventC.src[0]),
			Target:    C.GoString(&eventC.dest[0]),
			Data:      C.GoString(&eventC.data[0]),
		}

		switch eventC.op {
		case C.MOUNT:
			event.Operation = "mount"
		case C.UMOUNT:
			event.Operation = "umount"
		default:
			event.Operation = "unknown"
		}

		event.Flags = DecodeFlags(uint64(eventC.flags))

		if t.enricher != nil {
			t.enricher.Enrich(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(event)
	}
}
