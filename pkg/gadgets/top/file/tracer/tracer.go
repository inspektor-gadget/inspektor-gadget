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
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/file/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type file_stat -type file_id -cc clang filetop ./bpf/filetop.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
	TargetPid  int
	AllFiles   bool
	MaxRows    int
	Interval   time.Duration
	SortBy     []string
}

type Tracer struct {
	config        *Config
	objs          filetopObjects
	readLink      link.Link
	writeLink     link.Link
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*top.Event[types.Stats])
	done          chan bool
	colMap        columns.ColumnMap[types.Stats]
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*top.Event[types.Stats]),
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

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		t.Stop()
		return nil, err
	}
	t.colMap = statCols.GetColumnMap()

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

func (t *Tracer) nextStats() ([]*types.Stats, error) {
	stats := []*types.Stats{}

	var prev *filetopFileId = nil
	key := filetopFileId{}
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
		fileStat := filetopFileStat{}
		if err := entries.Lookup(key, unsafe.Pointer(&fileStat)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			Reads:         fileStat.Reads,
			Writes:        fileStat.Writes,
			ReadBytes:     fileStat.ReadBytes,
			WriteBytes:    fileStat.WriteBytes,
			Pid:           fileStat.Pid,
			Tid:           fileStat.Tid,
			Filename:      gadgets.FromCString(fileStat.Filename[:]),
			Comm:          gadgets.FromCString(fileStat.Comm[:]),
			FileType:      byte(fileStat.Type),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: fileStat.MntnsId},
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&stat.CommonData, stat.MountNsID)
		}

		stats = append(stats, &stat)

		prev = &key
		if err := entries.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	top.SortStats(stats, t.config.SortBy, &t.colMap)

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
					t.eventCallback(&top.Event[types.Stats]{
						Error: err.Error(),
					})
					return
				}

				n := len(stats)
				if n > t.config.MaxRows {
					n = t.config.MaxRows
				}
				t.eventCallback(&top.Event[types.Stats]{Stats: stats[:n]})
			}
		}
	}()
}

func (t *Tracer) Start() error {
	if err := t.start(); err != nil {
		t.Stop()
		return err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		t.Stop()
		return err
	}
	t.colMap = statCols.GetColumnMap()

	return nil
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*types.Stats))
	if !ok {
		panic("event handler invalid")
	}

	// TODO: add errorHandler
	t.eventCallback = func(ev *top.Event[types.Stats]) {
		if ev.Error != "" {
			return
		}
		nh(ev.Stats)
	}
}

func (t *Tracer) SetMountNsMap(mntnsMap *ebpf.Map) {
	t.config.MountnsMap = mntnsMap
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
		done:   make(chan bool),
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.MaxRows = params.Get(gadgets.ParamMaxRows).AsInt()
	t.config.SortBy = params.Get(gadgets.ParamSortBy).AsStringSlice()
	t.config.Interval = time.Second * time.Duration(params.Get(gadgets.ParamInterval).AsInt())
	t.config.AllFiles = params.Get(types.AllFilesParam).AsBool()
	return nil
}
