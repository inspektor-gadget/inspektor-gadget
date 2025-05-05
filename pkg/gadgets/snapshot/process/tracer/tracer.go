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
	"path/filepath"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type process_entry processCollector ./bpf/process-collector.bpf.c -- -Werror -O2 -g -c -x c

type Config struct {
	MountnsMap  *ebpf.Map
	ShowThreads bool
}

func RunCollector(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*processcollectortypes.Event, error) {
	events, err := runeBPFCollector(config, enricher)
	if err == nil {
		return events, nil
	}

	if !errors.Is(err, ebpf.ErrNotSupported) {
		return nil, fmt.Errorf("running ebpf iterator: %w", err)
	}

	events, err = runProcfsCollector(config, enricher)
	if err != nil {
		return nil, fmt.Errorf("running procfs collector: %w", err)
	}

	return events, err
}

func runeBPFCollector(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*processcollectortypes.Event, error) {
	spec, err := loadProcessCollector()
	if err != nil {
		return nil, fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"show_threads": config.ShowThreads,
	}
	objs := processCollectorObjects{}

	if err := gadgets.LoadeBPFSpec(config.MountnsMap, spec, consts, &objs); err != nil {
		return nil, fmt.Errorf("loading ebpf spec: %w", err)
	}

	defer objs.Close()

	dumpTaskIter, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapProc,
	})
	if err != nil {
		return nil, fmt.Errorf("attaching BPF iterator: %w", err)
	}
	defer dumpTaskIter.Close()

	buf, err := bpfiterns.Read(dumpTaskIter)
	if err != nil {
		return nil, fmt.Errorf("reading iterator: %w", err)
	}

	events := []*processcollectortypes.Event{}

	entrySize := int(unsafe.Sizeof(processCollectorProcessEntry{}))

	for i := 0; i < len(buf)/entrySize; i++ {
		entry := (*processCollectorProcessEntry)(unsafe.Pointer(&buf[i*entrySize]))

		event := processcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Pid:           int(entry.Tgid),
			Tid:           int(entry.Pid),
			Uid:           entry.Uid,
			Gid:           entry.Gid,
			Command:       gadgets.FromCString(entry.Comm[:]),
			ParentPid:     int(entry.ParentPid),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: entry.MntnsId},
		}

		if enricher != nil {
			enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		events = append(events, &event)
	}

	return events, nil
}

func getTidEvent(config *Config, enricher gadgets.DataEnricherByMntNs, pid, tid int) (*processcollectortypes.Event, error) {
	var val uint32

	comm := host.GetProcComm(tid)
	mntnsid, err := containerutils.GetMntNs(tid)
	if err != nil {
		return nil, err
	}

	if config.MountnsMap != nil {
		// TODO: This would be more efficient to store these elements in user space to avoid
		// performing systemcalls to lookup in the eBPF map
		err := config.MountnsMap.Lookup(&mntnsid, &val)
		if err != nil {
			return nil, err
		}
	}

	taskPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "task", fmt.Sprint(tid))
	info, err := os.Lstat(taskPath)
	if err != nil {
		return nil, fmt.Errorf("getting user of process: %w", err)
	}

	stat := info.Sys().(*syscall.Stat_t)

	event := &processcollectortypes.Event{
		Event: eventtypes.Event{
			Type: eventtypes.NORMAL,
		},
		Tid:           tid,
		Pid:           pid,
		Uid:           stat.Uid,
		Gid:           stat.Gid,
		Command:       comm,
		WithMountNsID: eventtypes.WithMountNsID{MountNsID: mntnsid},
	}

	if enricher != nil {
		enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
	}

	return event, nil
}

func getPidEvents(config *Config, enricher gadgets.DataEnricherByMntNs, pid int) ([]*processcollectortypes.Event, error) {
	var events []*processcollectortypes.Event

	taskPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "task")
	items, err := os.ReadDir(taskPath)
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if !item.IsDir() {
			continue
		}

		tid, err := strconv.ParseInt(item.Name(), 10, strconv.IntSize)
		if err != nil {
			continue
		}

		event, err := getTidEvent(config, enricher, pid, int(tid))
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

func runProcfsCollector(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*processcollectortypes.Event, error) {
	items, err := os.ReadDir(host.HostProcFs)
	if err != nil {
		return nil, err
	}

	events := []*processcollectortypes.Event{}

	for _, item := range items {
		if !item.IsDir() {
			continue
		}

		pid, err := strconv.ParseInt(item.Name(), 10, strconv.IntSize)
		if err != nil {
			continue
		}

		if config.ShowThreads {
			pidEvents, err := getPidEvents(config, enricher, int(pid))
			if err != nil {
				continue
			}
			events = append(events, pidEvents...)
		} else {
			event, err := getTidEvent(config, enricher, int(pid), int(pid))
			if err != nil {
				continue
			}
			events = append(events, event)
		}
	}

	return events, nil
}

// ---

type Tracer struct {
	config       *Config
	eventHandler func(ev []*processcollectortypes.Event)
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*processcollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

func (t *Tracer) SetMountNsMap(mntnsMap *ebpf.Map) {
	t.config.MountnsMap = mntnsMap
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.config.ShowThreads = gadgetCtx.GadgetParams().Get(ParamThreads).AsBool()

	processes, err := RunCollector(t.config, nil)
	if err != nil {
		return fmt.Errorf("running snapshotter: %w", err)
	}
	t.eventHandler(processes)
	return nil
}
