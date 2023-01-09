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

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containerutils "github.com/inspektor-gadget/inspektor-gadget/pkg/container-utils"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang processCollector ./bpf/process-collector.bpf.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c

type Config struct {
	MountnsMap *ebpf.Map
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

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return nil, fmt.Errorf("error RewriteConstants: %w", err)
	}

	objs := processCollectorObjects{}
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
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

	var events []*processcollectortypes.Event

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var command string
		var tgid, pid, parentPid int
		var mntnsid uint64

		text := scanner.Text()
		matchedElems, err := fmt.Sscanf(text, "%d %d %d %d", &tgid, &pid, &parentPid, &mntnsid)
		if err != nil {
			return nil, fmt.Errorf("failed to parse process information: %w", err)
		}
		if matchedElems != 4 {
			return nil, fmt.Errorf("failed to parse process information, expected 4 integers had %d", matchedElems)
		}
		textSplit := strings.SplitN(text, " ", 5)
		if len(textSplit) != 5 {
			return nil, fmt.Errorf("failed to parse process information, expected 5 matched elements had %d", len(textSplit))
		}
		command = textSplit[4]

		event := processcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Pid:       tgid,
			Tid:       pid,
			Command:   command,
			ParentPid: parentPid,
			MountNsID: mntnsid,
		}

		if enricher != nil {
			enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		events = append(events, &event)
	}

	return events, nil
}

func getPidEvents(config *Config, enricher gadgets.DataEnricherByMntNs, pid int) ([]*processcollectortypes.Event, error) {
	var events []*processcollectortypes.Event
	var val uint32

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

		commBytes, _ := os.ReadFile(filepath.Join(hostRoot, fmt.Sprintf("/proc/%d/comm", tid)))
		comm := strings.TrimRight(string(commBytes), "\n")
		mntnsid, err := containerutils.GetMntNs(tid)
		if err != nil {
			continue
		}

		if config.MountnsMap != nil {
			// TODO: This would be more efficient to store
			// these elements in user space to avoid
			// performing systemcalls to lookup in the eBPF
			// map
			err := config.MountnsMap.Lookup(&mntnsid, &val)
			if err != nil {
				continue
			}
		}

		f, err := os.Open(filepath.Join(hostRoot, fmt.Sprintf("/proc/%d/status", tid)))
		if err != nil {
			continue
		}

		parentPid := -1
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			matchedElems, err := fmt.Sscanf(scanner.Text(), "PPid:\t%d", &parentPid)
			if err != nil {
				continue
			}

			if matchedElems != 1 {
				continue
			}

			break
		}

		f.Close()

		event := processcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Tid:       tid,
			Pid:       pid,
			Command:   comm,
			ParentPid: parentPid,
			MountNsID: mntnsid,
		}

		if enricher != nil {
			enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		events = append(events, &event)
	}

	return events, nil
}

func runProcfsCollector(config *Config, enricher gadgets.DataEnricherByMntNs) ([]*processcollectortypes.Event, error) {
	items, err := os.ReadDir(filepath.Join(hostRoot, "/proc/"))
	if err != nil {
		return nil, err
	}

	var events []*processcollectortypes.Event

	for _, item := range items {
		if !item.IsDir() {
			continue
		}

		pid64, err := strconv.ParseUint(item.Name(), 10, 32)
		if err != nil {
			continue
		}
		pid := int(pid64)

		pidEvents, err := getPidEvents(config, enricher, pid)
		if err != nil {
			continue
		}

		events = append(events, pidEvents...)
	}

	return events, nil
}
