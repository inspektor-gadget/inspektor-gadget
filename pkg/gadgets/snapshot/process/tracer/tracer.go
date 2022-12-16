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
	"fmt"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/process/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang processCollector ./bpf/process-collector.bpf.c -- -I../../../../${TARGET} -Werror -O2 -g -c -x c

func RunCollector(enricher gadgets.DataEnricher, mntnsmap *ebpf.Map) ([]*processcollectortypes.Event, error) {
	spec, err := loadProcessCollector()
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if mntnsmap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = mntnsmap
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
		var tgid, pid int
		var mntnsid uint64

		text := scanner.Text()
		matchedElems, err := fmt.Sscanf(text, "%d %d %d", &tgid, &pid, &mntnsid)
		if err != nil {
			return nil, err
		}
		if matchedElems != 3 {
			return nil, fmt.Errorf("failed to parse process information, expected 3 integers had %d", matchedElems)
		}
		textSplit := strings.SplitN(text, " ", 4)
		if len(textSplit) != 4 {
			return nil, fmt.Errorf("failed to parse process information, expected 4 matched elements had %d", len(textSplit))
		}
		command = textSplit[3]

		event := processcollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			Pid:       tgid,
			Tid:       pid,
			Command:   command,
			MountNsID: mntnsid,
		}

		if enricher != nil {
			enricher.Enrich(&event.CommonData, event.MountNsID)
		}

		events = append(events, &event)
	}

	return events, nil
}
