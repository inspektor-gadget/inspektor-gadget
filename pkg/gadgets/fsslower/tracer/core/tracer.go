//go:build linux
// +build linux

// Copyright 2022 The Inspektor Gadget authors
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
// #include "./bpf/fsslower.h"
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
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/fsslower/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/fsslower/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang fsslower ./bpf/fsslower.bpf.c -- -I./bpf/ -I../../../../ -target bpf -D__TARGET_ARCH_x86"

type Tracer struct {
	config        *tracer.Config
	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string

	objs           fsslowerObjects
	readEnterLink  link.Link
	readExitLink   link.Link
	writeEnterLink link.Link
	writeExitLink  link.Link
	openEnterLink  link.Link
	openExitLink   link.Link
	syncEnterLink  link.Link
	syncExitLink   link.Link
	reader         *perf.Reader
}

type fsConf struct {
	read  string
	write string
	open  string
	fsync string
}

var fsConfMap = map[string]fsConf{
	"btrfs": {
		read:  "btrfs_file_read_iter",
		write: "btrfs_file_write_iter",
		open:  "btrfs_file_open",
		fsync: "btrfs_sync_file",
	},
	"ext4": {
		read:  "ext4_file_read_iter",
		write: "ext4_file_write_iter",
		open:  "ext4_file_open",
		fsync: "ext4_sync_file",
	},
	"nfs": {
		read:  "nfs_file_read",
		write: "nfs_file_write",
		open:  "nfs_file_open",
		fsync: "nfs_file_fsync",
	},
	"xfs": {
		read:  "xfs_file_read_iter",
		write: "xfs_file_write_iter",
		open:  "xfs_file_open",
		fsync: "xfs_file_fsync",
	},
}

func NewTracer(config *tracer.Config, resolver containercollection.ContainerResolver,
	eventCallback func(types.Event), node string) (*Tracer, error) {
	t := &Tracer{
		config:        config,
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
	// read
	t.readEnterLink = gadgets.CloseLink(t.readEnterLink)
	t.readExitLink = gadgets.CloseLink(t.readExitLink)

	// write
	t.writeEnterLink = gadgets.CloseLink(t.writeEnterLink)
	t.writeExitLink = gadgets.CloseLink(t.writeExitLink)

	// open
	t.openEnterLink = gadgets.CloseLink(t.openEnterLink)
	t.openExitLink = gadgets.CloseLink(t.openExitLink)

	// sync
	t.syncEnterLink = gadgets.CloseLink(t.syncEnterLink)
	t.syncExitLink = gadgets.CloseLink(t.syncExitLink)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	var err error

	spec, err := loadFsslower()
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
		"min_lat_ns":       uint64(t.config.MinLatency * 1000 * 1000),
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

	// choose a configuration based on the filesystem type passed
	fsConf, ok := fsConfMap[t.config.Filesystem]
	if !ok {
		return fmt.Errorf("%q is not a supported filesystem", t.config.Filesystem)
	}

	// read
	t.readEnterLink, err = link.Kprobe(fsConf.read, t.objs.FileReadEntry, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}
	t.readExitLink, err = link.Kretprobe(fsConf.read, t.objs.FileReadExit, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	// write
	t.writeEnterLink, err = link.Kprobe(fsConf.write, t.objs.FileWriteEntry, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}
	t.writeExitLink, err = link.Kretprobe(fsConf.write, t.objs.FileWriteExit, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	// open
	t.openEnterLink, err = link.Kprobe(fsConf.open, t.objs.FileOpenEntry, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}
	t.openExitLink, err = link.Kretprobe(fsConf.open, t.objs.FileOpenExit, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	// sync
	t.syncEnterLink, err = link.Kprobe(fsConf.fsync, t.objs.FileSyncEntry, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}
	t.syncExitLink, err = link.Kretprobe(fsConf.fsync, t.objs.FileSyncExit, nil)
	if err != nil {
		return fmt.Errorf("error attaching program: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.fsslowerMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}

	go t.run()

	return nil
}

var ops = []string{"R", "W", "O", "F"}

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

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
			},
			MountNsID: uint64(eventC.mntns_id),
			Comm:      C.GoString(&eventC.task[0]),
			Pid:       uint32(eventC.pid),
			Op:        ops[int(eventC.op)],
			Bytes:     uint64(eventC.size),
			Offset:    int64(eventC.offset),
			Latency:   uint64(eventC.delta_us),
			File:      C.GoString(&eventC.file[0]),
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
