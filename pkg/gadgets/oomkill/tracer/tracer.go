//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
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
// #include "./bpf/oomkill.h"
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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/oomkill/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang oomkill ./bpf/oomkill.bpf.c -- -I./bpf/ -I../../.. -target bpf -D__TARGET_ARCH_x86"

type Config struct {
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config        *Config
	objs          oomkillObjects
	oomLink       link.Link
	reader        *perf.Reader
	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string
}

func NewTracer(c *Config, resolver containercollection.ContainerResolver, eventCallback func(types.Event), node string) (*Tracer, error) {
	t := &Tracer{
		config:        c,
		resolver:      resolver,
		eventCallback: eventCallback,
		node:          node,
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.stop()
}

func (t *Tracer) stop() {
	t.oomLink = gadgets.CloseLink(t.oomLink)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadOomkill()
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

	kprobe, err := link.Kprobe("oom_kill_process", t.objs.OomKillProcess, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.oomLink = kprobe

	reader, err := perf.NewReader(t.objs.oomkillMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
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
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
			return
		}

		eventC := (*C.struct_data_t)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
			},
			TriggeredPid:  uint32(eventC.fpid),
			TriggeredComm: C.GoString(&eventC.fcomm[0]),
			KilledPid:     uint32(eventC.tpid),
			KilledComm:    C.GoString(&eventC.tcomm[0]),
			Pages:         uint64(eventC.pages),
			MountNsID:     uint64(eventC.mount_ns_id),
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
