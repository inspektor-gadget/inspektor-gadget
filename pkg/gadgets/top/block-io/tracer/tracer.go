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
	"context"
	"errors"
	"fmt"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/block-io/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type info_t -type val_t -cc clang biotop ./bpf/biotop.bpf.c -- -I./bpf/ -I../../../../${TARGET}  -I ../../../common/

type Config struct {
	MaxRows    int
	Interval   time.Duration
	Iterations int
	SortBy     []string
	MountnsMap *ebpf.Map
}

type Tracer struct {
	config           *Config
	objs             biotopObjects
	ioStartLink      link.Link
	startRequestLink link.Link
	doneLink         link.Link
	enricher         gadgets.DataEnricherByMntNs
	eventCallback    func(*top.Event[types.Stats])
	done             chan bool
	colMap           columns.ColumnMap[types.Stats]
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

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		t.close()
		return nil, err
	}
	t.colMap = statCols.GetColumnMap()

	go t.run(context.TODO())

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	close(t.done)

	t.ioStartLink = gadgets.CloseLink(t.ioStartLink)
	t.startRequestLink = gadgets.CloseLink(t.startRequestLink)
	t.doneLink = gadgets.CloseLink(t.doneLink)

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadBiotop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, nil, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	kernelSymbols, err := kallsyms.NewKAllSyms()
	if err != nil {
		return fmt.Errorf("failed to load kernel symbols: %w", err)
	}

	// __blk_account_io_start and __blk_account_io_done were inlined in:
	// be6bfe36db17 ("block: inline hot paths of blk_account_io_*()").
	// which was included in kernel 5.16.
	// So let's be future proof and check if these symbols do not exist.
	blkAccountIoStartFunction := "__blk_account_io_start"
	if !kernelSymbols.SymbolExists(blkAccountIoStartFunction) {
		blkAccountIoStartFunction = "blk_account_io_start"
	}

	blkAccountIoDoneFunction := "__blk_account_io_done"
	if !kernelSymbols.SymbolExists(blkAccountIoDoneFunction) {
		blkAccountIoDoneFunction = "blk_account_io_done"
	}

	t.ioStartLink, err = link.Kprobe(blkAccountIoStartFunction, t.objs.IgTopioStart, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.startRequestLink, err = link.Kprobe("blk_mq_start_request", t.objs.IgTopioReq, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.doneLink, err = link.Kprobe(blkAccountIoDoneFunction, t.objs.IgTopioDone, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	return nil
}

func (t *Tracer) nextStats() ([]*types.Stats, error) {
	stats := []*types.Stats{}

	var prev *biotopInfoT = nil
	key := biotopInfoT{}
	counts := t.objs.Counts

	defer func() {
		// delete elements
		err := counts.NextKey(nil, unsafe.Pointer(&key))
		if err != nil {
			return
		}

		for {
			if err := counts.Delete(key); err != nil {
				return
			}

			prev = &key
			if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
				return
			}
		}
	}()

	// gather elements
	err := counts.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		val := biotopValT{}
		if err := counts.Lookup(key, unsafe.Pointer(&val)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			Write:         key.Rwflag != 0,
			Major:         int(key.Major),
			Minor:         int(key.Minor),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: key.Mntnsid},
			Pid:           int32(key.Pid),
			Comm:          gadgets.FromCString(key.Name[:]),
			Bytes:         val.Bytes,
			MicroSecs:     val.Us,
			Operations:    val.Io,
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&stat.CommonData, stat.MountNsID)
		}

		stats = append(stats, &stat)

		prev = &key
		if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	top.SortStats(stats, t.config.SortBy, &t.colMap)

	return stats, nil
}

func (t *Tracer) run(ctx context.Context) error {
	// Don't use a context with a timeout but a counter to avoid having to deal
	// with two timers: one for the timeout and another for the ticker.
	count := t.config.Iterations
	ticker := time.NewTicker(t.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			// TODO: Once we completely move to use Run instead of NewTracer,
			// we can remove this as nobody will directly call Stop (cleanup).
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := t.nextStats()
			if err != nil {
				return fmt.Errorf("getting next stats: %w", err)
			}

			n := len(stats)
			if n > t.config.MaxRows {
				n = t.config.MaxRows
			}
			t.eventCallback(&top.Event[types.Stats]{Stats: stats[:n]})

			// Count down only if user requested a finite number of iterations
			// through a timeout.
			if t.config.Iterations > 0 {
				count--
				if count == 0 {
					return nil
				}
			}
		}
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	if err := t.init(gadgetCtx); err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	return t.run(gadgetCtx.Context())
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
		config: &Config{
			MaxRows:  20,
			Interval: 1 * time.Second,
			SortBy:   nil,
		},
		done: make(chan bool),
	}
	return tracer, nil
}

func (t *Tracer) init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.MaxRows = params.Get(gadgets.ParamMaxRows).AsInt()
	t.config.SortBy = params.Get(gadgets.ParamSortBy).AsStringSlice()
	t.config.Interval = time.Second * time.Duration(params.Get(gadgets.ParamInterval).AsInt())

	var err error
	if t.config.Iterations, err = top.ComputeIterations(t.config.Interval, gadgetCtx.Timeout()); err != nil {
		return err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		return err
	}
	t.colMap = statCols.GetColumnMap()

	return nil
}
