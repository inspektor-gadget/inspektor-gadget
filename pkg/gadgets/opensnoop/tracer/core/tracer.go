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
// #include "./bpf/opensnoop.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/opensnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang opensnoop ./bpf/opensnoop.bpf.c -- -I./bpf/ -I../../../../ -target bpf -D__TARGET_ARCH_x86"

type Tracer struct {
	config        *tracer.Config
	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string

	objs            opensnoopObjects
	openEnterLink   link.Link
	openAtEnterLink link.Link
	openExitLink    link.Link
	openAtExitLink  link.Link
	reader          *perf.Reader
}

func NewTracer(config *tracer.Config, resolver containercollection.ContainerResolver,
	eventCallback func(types.Event), node string) (*Tracer, error) {
	t := &Tracer{config: config}

	t.resolver = resolver
	t.eventCallback = eventCallback
	t.node = node

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.openEnterLink = gadgets.CloseLink(t.openEnterLink)
	t.openAtEnterLink = gadgets.CloseLink(t.openAtEnterLink)
	t.openExitLink = gadgets.CloseLink(t.openExitLink)
	t.openAtExitLink = gadgets.CloseLink(t.openAtExitLink)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadOpensnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
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

	openEnter, err := link.Tracepoint("syscalls", "sys_enter_open", t.objs.TracepointSyscallsSysEnterOpen, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openEnterLink = openEnter

	openAtEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", t.objs.TracepointSyscallsSysEnterOpenat, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openAtEnterLink = openAtEnter

	openExit, err := link.Tracepoint("syscalls", "sys_exit_open", t.objs.TracepointSyscallsSysExitOpen, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openExitLink = openExit

	openAtExit, err := link.Tracepoint("syscalls", "sys_exit_openat", t.objs.TracepointSyscallsSysExitOpenat, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}
	t.openAtExitLink = openAtExit

	reader, err := perf.NewReader(t.objs.opensnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg, t.node)))
			continue
		}

		eventC := (*C.struct_event)(unsafe.Pointer(&record.RawSample[0]))

		ret := int(eventC.ret)
		fd := 0
		errval := 0

		if ret >= 0 {
			fd = ret
		} else {
			errval = -ret
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
			},
			MountNsID: uint64(eventC.mntns_id),
			Pid:       uint32(eventC.pid),
			UID:       uint32(eventC.uid),
			Comm:      C.GoString(&eventC.comm[0]),
			Ret:       ret,
			Fd:        fd,
			Err:       errval,
			Path:      C.GoString(&eventC.fname[0]),
		}

		container := t.resolver.LookupContainerByMntns(event.MountNsID)
		if container != nil {
			event.Container = container.Name
			event.Pod = container.Podname
			event.Namespace = container.Namespace
		}

		t.eventCallback(event)
	}
}
