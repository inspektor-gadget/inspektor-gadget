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

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang ProcessCollector ./bpf/process-collector.c -- -I../../.. -Werror -O2 -g -c -x c"
//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang ProcessCollectorWithFilters ./bpf/process-collector.c -- -DWITH_FILTER=1 -I../../.. -Werror -O2 -g -c -x c"

const (
	BPFIterName = "dump_task"
)

func RunCollector(resolver gadgets.Resolver, node string, mntnsmap *ebpf.Map) ([]processcollectortypes.Event, error) {
	var err error
	var spec *ebpf.CollectionSpec

	if mntnsmap == nil {
		spec, err = LoadProcessCollector()
	} else {
		spec, err = LoadProcessCollectorWithFilters()
	}
	if err != nil {
		return nil, fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}

	if mntnsmap != nil {
		mapReplacements["filter"] = mntnsmap
	}

	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			MapReplacements: mapReplacements,
		})
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	dumpTask, ok := coll.Programs[BPFIterName]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF iterator %q", BPFIterName)
	}
	dumpTaskIter, err := link.AttachIter(link.IterOptions{
		Program: dumpTask,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attach BPF iterator: %w", err)
	}

	file, err := dumpTaskIter.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open BPF iterator: %w", err)
	}
	defer file.Close()

	var events []processcollectortypes.Event

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		var command string
		var tgid, pid int
		var mntnsid uint64

		matchedElems, err := fmt.Sscanf(scanner.Text(), "%d %d %s %d", &tgid, &pid, &command, &mntnsid)
		if err != nil {
			return nil, err
		}
		if matchedElems != 4 {
			return nil, fmt.Errorf("failed to parse process information, expected 4 matched elements had %d", matchedElems)
		}

		container := resolver.LookupContainerByMntns(mntnsid)
		if container == nil {
			continue
		}

		events = append(events, processcollectortypes.Event{
			Event: eventtypes.Event{
				Node:      node,
				Namespace: container.Namespace,
				Pod:       container.Podname,
				Container: container.Name,
			},
			Tgid:      tgid,
			Pid:       pid,
			Command:   command,
			MountNsID: mntnsid,
		})
	}

	return events, nil
}
