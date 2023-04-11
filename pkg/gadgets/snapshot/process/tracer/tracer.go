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
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang processCollector ./bpf/process-collector.bpf.c -- -I../../../../${TARGET} -I ../../../common/ -Werror -O2 -g -c -x c

type Config struct {
	MountnsMap  *ebpf.Map
	ShowThreads bool
}

var hostRoot string

func init() {
	hostRoot = os.Getenv("HOST_ROOT")
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
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"show_threads": config.ShowThreads,
	}
	objs := processCollectorObjects{}

	if err := gadgets.LoadeBPFSpec(config.MountnsMap, spec, consts, &objs, nil); err != nil {
		return nil, fmt.Errorf("loading ebpf spec: %w", err)
	}

	defer objs.Close()

	dumpTaskIter, err := link.AttachIter(link.IterOptions{
		Program: objs.IgSnapProc,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF iterator: %w", err)
	}
	defer dumpTaskIter.Close()

	file, err := dumpTaskIter.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open BPF iterator: %w", err)
	}
	defer file.Close()

	events := []*processcollectortypes.Event{}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var command string
		var tgid, pid, parentPid int
		var mntnsid uint64
		var uid, gid uint32

		text := scanner.Text()
		matchedElems, err := fmt.Sscanf(text, "%d %d %d %d %d %d", &tgid, &pid, &parentPid, &mntnsid, &uid, &gid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse process information: %w", err)
		}
		if matchedElems != 6 {
			return nil, fmt.Errorf("failed to parse process information, expected 4 integers had %d", matchedElems)
		}
		textSplit := strings.SplitN(text, " ", 7)
		if len(textSplit) != 7 {
			return nil, fmt.Errorf("failed to parse process information, expected 5 matched elements had %d", len(textSplit))
		}
		command = textSplit[6]

		event := processcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Pid:           tgid,
			Tid:           pid,
			Uid:           uid,
			Gid:           gid,
			Command:       command,
			ParentPid:     parentPid,
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mntnsid},
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

	commBytes, _ := os.ReadFile(filepath.Join(hostRoot, fmt.Sprintf("/proc/%d/comm", tid)))
	comm := strings.TrimRight(string(commBytes), "\n")
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

	info, err := os.Lstat(fmt.Sprintf("/proc/%d/task/%d", pid, tid))
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
		enricher.EnrichByMntNs(&event.CommonData, event.WithMountNsID.MountNsID)
	}

	return event, nil
}

func getPidEvents(config *Config, enricher gadgets.DataEnricherByMntNs, pid int) ([]*processcollectortypes.Event, error) {
	var events []*processcollectortypes.Event

	items, err := os.ReadDir(filepath.Join(hostRoot, fmt.Sprintf("/proc/%d/task/", pid)))
	if err != nil {
		return nil, err
	}

	for _, item := range items {
		if !item.IsDir() {
			continue
		}

		tid64, err := strconv.ParseUint(item.Name(), 10, 32)
		if err != nil {
			continue
		}
		tid := int(tid64)
		event, err := getTidEvent(config, enricher, pid, tid)
		if err != nil {
			continue
		}

		events = append(events, event)
	}

	return events, nil
}

func runProcfsCollector(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*processcollectortypes.Event, error) {
	items, err := os.ReadDir(filepath.Join(hostRoot, "/proc/"))
	if err != nil {
		return nil, err
	}

	events := []*processcollectortypes.Event{}

	for _, item := range items {
		if !item.IsDir() {
			continue
		}

		pid64, err := strconv.ParseUint(item.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := int(pid64)

		if config.ShowThreads {
			pidEvents, err := getPidEvents(config, enricher, pid)
			if err != nil {
				continue
			}
			events = append(events, pidEvents...)
		} else {
			event, err := getTidEvent(config, enricher, pid, pid)
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
	logger       logger.Logger
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
