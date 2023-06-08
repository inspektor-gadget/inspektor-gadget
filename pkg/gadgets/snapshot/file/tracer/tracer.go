// Copyright 2023 The Inspektor Gadget authors
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
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	filecollectortypes "github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/snapshot/file/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang iterFile ./bpf/file.c -- -I../../../../${TARGET} -I ../../../common/ -Werror -O2 -g -c -x c

type Tracer struct {
	iter       *link.Iter
	MountnsMap *ebpf.Map

	eventHandler func([]*filecollectortypes.Event)
}

func (t *Tracer) loadIter() error {
	spec, err := loadIterFile()
	if err != nil {
		return fmt.Errorf("load files BPF programs: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements[gadgets.MntNsFilterMapName] = t.MountnsMap
	}

	consts := map[string]interface{}{
		gadgets.FilterByMntNsName: filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("RewriteConstants: %w", err)
	}

	err = kallsyms.SpecUpdateAddresses(spec, []string{
		"socket_file_ops",
		"bpf_map_fops",
		"bpf_prog_fops",
		"bpf_link_fops",
		"eventpoll_fops",
		"tty_fops",
	})
	if err != nil {
		return fmt.Errorf("SpecUpdateAddresses: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	objs := &iterFileObjects{}
	if err := spec.LoadAndAssign(objs, &opts); err != nil {
		var errVerifier *ebpf.VerifierError
		if errors.As(err, &errVerifier) {
			fmt.Printf("Error: %+v\n", errVerifier)
		}
		return fmt.Errorf("load files BPF iterator: %w", err)
	}
	defer objs.Close()

	t.iter, err = link.AttachIter(link.IterOptions{
		Program: objs.IgFileIt,
	})
	if err != nil {
		return fmt.Errorf("attach files BPF iterator: %w", err)
	}

	return nil
}

// RunCollector is currently exported so it can be called from Collect()
func (t *Tracer) RunCollector() ([]*filecollectortypes.Event, error) {
	kAllSyms, err := kallsyms.NewKAllSyms()
	if err != nil {
		return nil, fmt.Errorf("reading kallsyms: %w", err)
	}

	files := []*filecollectortypes.Event{}

	reader, err := t.iter.Open()
	if err != nil {
		return nil, fmt.Errorf("open BPF iterator: %w", err)
	}
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	privateData := ""
	for scanner.Scan() {
		var inodeNumber uint64
		var mntns uint64
		var netns uint32
		var command string
		var pid, parentPid int
		var uid, gid uint32
		var fd int
		var fops uint64

		text := scanner.Text()
		if !strings.HasPrefix(text, "####") {
			privateData = privateData + text + "\n"
			continue
		}
		matchedElems, err := fmt.Sscanf(text, "#### %d %d %d %d %d %d %d %d",
			&mntns,
			&parentPid, &pid, &uid, &gid, &fd, &inodeNumber, &fops)
		if err != nil {
			return nil, fmt.Errorf("parse files information (%q): %w", text, err)
		}
		if matchedElems != 8 {
			return nil, fmt.Errorf("parse files information: found %d fields", matchedElems)
		}
		textSplit := strings.SplitN(text, " ", 10)
		if len(textSplit) != 10 {
			return nil, fmt.Errorf("parsing process information, expected 9 matched elements had %d", len(textSplit))
		}
		command = textSplit[9]

		typ := kAllSyms.LookupByAddress(fops)
		typ = strings.TrimSuffix(typ, "_fops")
		typ = strings.TrimSuffix(typ, "_ops")
		typ = strings.TrimSuffix(typ, "_file_operations")

		files = append(files, &filecollectortypes.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: mntns},
			WithNetNsID:   eventtypes.WithNetNsID{NetNsID: uint64(netns)},
			Pid:           pid,
			Uid:           uid,
			Gid:           gid,
			Command:       command,
			ParentPid:     parentPid,
			Fd:            fd,
			Type:          typ,
			InodeNumber:   inodeNumber,
			Private:       privateData,
		})
		privateData = ""
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading output of BPF iterator: %w", err)
	}

	return files, nil
}

// ---

func NewTracer() (*Tracer, error) {
	tracer := &Tracer{}

	if err := tracer.loadIter(); err != nil {
		tracer.CloseIter()
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	return tracer, nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{}, nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*filecollectortypes.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventHandler = nh
}

// CloseIter is currently exported so it can be called from Collect()
func (t *Tracer) CloseIter() {
	if t.iter != nil {
		t.iter.Close()
	}
	t.iter = nil
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	defer t.CloseIter()
	if err := t.loadIter(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	allFiles := []*filecollectortypes.Event{}
	// TODO: Remove podname, namespace and node arguments from RunCollector.
	// The enrichment will be done in the event handler. In addition, pass
	// the netns to avoid retrieving it again in RunCollector.
	files, err := t.RunCollector()
	if err != nil {
		return fmt.Errorf("read files: %w", err)
	}
	allFiles = append(allFiles, files...)

	t.eventHandler(allFiles)
	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.MountnsMap = mountnsMap
}
