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
	"bytes"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	processcollectortypes "github.com/kinvolk/inspektor-gadget/pkg/gadgets/process-collector/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

const (
	BPF_ITER_NAME = "dump_task"
)

func RunCollector(resolver gadgets.Resolver, node, mntnsmap string) ([]processcollectortypes.Event, error) {
	var prog []byte
	if mntnsmap == "" {
		prog = ebpfProg
	} else {
		if filepath.Dir(mntnsmap) != gadgets.PIN_PATH {
			return nil, fmt.Errorf("error while checking pin path: only paths in %s are supported", gadgets.PIN_PATH)
		}

		prog = ebpfProgWithFilter
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return nil, fmt.Errorf("failed to load asset: %w", err)
	}

	if mntnsmap != "" {
		spec.Maps["filter"].Name = filepath.Base(mntnsmap)
		spec.Maps["filter"].Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: gadgets.PIN_PATH,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create BPF collection: %w", err)
	}

	dumpTask, ok := coll.Programs[BPF_ITER_NAME]
	if !ok {
		return nil, fmt.Errorf("failed to find BPF iterator %q", BPF_ITER_NAME)
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
			Tgid:    tgid,
			Pid:     pid,
			Command: command,
			MntNsId: mntnsid,
		})
	}

	return events, nil
}
