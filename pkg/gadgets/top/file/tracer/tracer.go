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

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #include <linux/types.h>
// #include "./bpf/filetop.h"
import "C"

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang filetop ./bpf/filetop.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
	TargetPid  int
	AllFiles   bool
	MaxRows    int
	Interval   time.Duration
	SortBy     types.SortBy
}

type Tracer struct {
	config        *Config
	objs          filetopObjects
	readLink      link.Link
	writeLink     link.Link
	enricher      gadgets.DataEnricher
	eventCallback func(*types.Event)
	done          chan bool
}

func NewTracer(config *Config, enricher gadgets.DataEnricher,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
		done:          make(chan bool),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	close(t.done)

	t.readLink = gadgets.CloseLink(t.readLink)
	t.writeLink = gadgets.CloseLink(t.writeLink)

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadFiletop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"target_pid":        uint32(t.config.TargetPid),
		"regular_file_only": !t.config.AllFiles,
		"filter_by_mnt_ns":  filterByMntNs,
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

	kpread, err := link.Kprobe("vfs_read", t.objs.IgTopfileRdE, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.readLink = kpread

	kpwrite, err := link.Kprobe("vfs_write", t.objs.IgTopfileWrE, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.writeLink = kpwrite

	t.run()

	return nil
}

func (t *Tracer) nextStats() ([]types.Stats, error) {
	stats := []types.Stats{}

	var prev *C.struct_file_id = nil
	key := C.struct_file_id{}
	entries := t.objs.Entries

	defer func() {
		// delete elements
		err := entries.NextKey(nil, unsafe.Pointer(&key))
		if err != nil {
			return
		}

		for {
			if err := entries.Delete(key); err != nil {
				return
			}

			prev = &key
			if err := entries.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
				return
			}
		}
	}()

	// gather elements
	err := entries.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		fileStat := C.struct_file_stat{}
		if err := entries.Lookup(key, unsafe.Pointer(&fileStat)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			Reads:      uint64(fileStat.reads),
			Writes:     uint64(fileStat.writes),
			ReadBytes:  uint64(fileStat.read_bytes),
			WriteBytes: uint64(fileStat.write_bytes),
			Pid:        uint32(fileStat.pid),
			Tid:        uint32(fileStat.tid),
			Filename:   C.GoString(&fileStat.filename[0]),
			Comm:       C.GoString(&fileStat.comm[0]),
			FileType:   byte(fileStat.type_),
			MountNsID:  uint64(fileStat.mntns_id),
		}

		if t.enricher != nil {
			t.enricher.Enrich(&stat.CommonData, stat.MountNsID)
		}

		stats = append(stats, stat)

		prev = &key
		if err := entries.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	types.SortStats(stats, t.config.SortBy)

	return stats, nil
}

func (t *Tracer) run() {
	ticker := time.NewTicker(t.config.Interval)

	go func() {
		for {
			select {
			case <-t.done:
			case <-ticker.C:
				stats, err := t.nextStats()
				if err != nil {
					t.eventCallback(&types.Event{
						Error: err.Error(),
					})
					return
				}

				n := len(stats)
				if n > t.config.MaxRows {
					n = t.config.MaxRows
				}
				t.eventCallback(&types.Event{Stats: stats[:n]})
			}
		}
	}()
}
