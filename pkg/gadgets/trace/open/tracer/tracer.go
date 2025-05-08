// Copyright 2019-2024 The Inspektor Gadget authors
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
	"io/fs"
	"os"
	"runtime"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/open/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target bpfel -cc clang -cflags ${CFLAGS} -type event -type prefix_key opensnoop ./bpf/opensnoop.bpf.c -- -I./bpf/

const (
	// Keep in sync with opensnoop.h.
	NAME_MAX = 255
	// Keep in sync with opensnoop.bpf.c.
	CHAR_BIT = 8
)

// needs to be kept in sync with opensnoopEvent from opensnoop_bpfel.go without the FullFname field
type opensnoopEventAbbrev struct {
	Timestamp uint64
	Pid       uint32
	Tid       uint32
	Uid       uint32
	Gid       uint32
	MntnsId   uint64
	Err       int32
	Fd        uint32
	Flags     int32
	Mode      uint16
	Comm      [16]uint8
	Fname     [255]uint8
}

type Config struct {
	MountnsMap *ebpf.Map
	FullPath   bool
	Prefixes   []string
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs            opensnoopObjects
	openEnterLink   link.Link
	openAtEnterLink link.Link
	openExitLink    link.Link
	openAtExitLink  link.Link
	reader          *perf.Reader
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	go t.run()

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	t.openEnterLink = gadgets.CloseLink(t.openEnterLink)
	t.openAtEnterLink = gadgets.CloseLink(t.openAtEnterLink)
	t.openExitLink = gadgets.CloseLink(t.openExitLink)
	t.openAtExitLink = gadgets.CloseLink(t.openAtExitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadOpensnoop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	prefixesNumber := uint32(len(t.config.Prefixes))
	prefixesMax := spec.Maps["prefixes"].MaxEntries
	if prefixesNumber > prefixesMax {
		return fmt.Errorf("%d maximum prefixes supported, got %d", prefixesMax, prefixesNumber)
	}

	consts := make(map[string]interface{})
	consts["get_full_path"] = t.config.FullPath
	consts["prefixes_nr"] = prefixesNumber

	for _, prefix := range t.config.Prefixes {
		var pfx [NAME_MAX]uint8

		bytes := uint32(len(prefix))
		if bytes > NAME_MAX {
			bytes = NAME_MAX
		}
		copy(pfx[:], prefix)

		spec.Maps["prefixes"].Contents = append(spec.Maps["prefixes"].Contents, ebpf.MapKV{
			// We need to give the exact length of the prefix here.
			// Otherwise, the kernel will compare until NAME_MAX * CHAR_BIT and there
			// will never be a match (unless the filename is NAME_MAX long and equals
			// to the prefix).
			Key:   opensnoopPrefixKey{Prefixlen: bytes * CHAR_BIT, Filename: pfx},
			Value: uint8(0),
		})
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	// arm64 does not define the open() syscall, only openat().
	if runtime.GOARCH != "arm64" {
		openEnter, err := link.Tracepoint("syscalls", "sys_enter_open", t.objs.IgOpenE, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint: %w", err)
		}
		t.openEnterLink = openEnter
	}

	openAtEnter, err := link.Tracepoint("syscalls", "sys_enter_openat", t.objs.IgOpenatE, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.openAtEnterLink = openAtEnter

	if runtime.GOARCH != "arm64" {
		openExit, err := link.Tracepoint("syscalls", "sys_exit_open", t.objs.IgOpenX, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint: %w", err)
		}
		t.openExitLink = openExit
	}

	openAtExit, err := link.Tracepoint("syscalls", "sys_exit_openat", t.objs.IgOpenatX, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.openAtExitLink = openAtExit

	reader, err := perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	t.reader = reader

	if err := gadgets.FreezeMaps(t.objs.Events); err != nil {
		return err
	}

	return nil
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				// nothing to do, we're done
				return
			}

			msg := fmt.Sprintf("reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		bpfEvent := (*opensnoopEventAbbrev)(unsafe.Pointer(&record.RawSample[0]))

		mode := fs.FileMode(bpfEvent.Mode)

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Pid:           bpfEvent.Pid,
			Tid:           bpfEvent.Tid,
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Fd:            bpfEvent.Fd,
			Err:           bpfEvent.Err,
			FlagsRaw:      bpfEvent.Flags,
			Flags:         DecodeFlags(bpfEvent.Flags),
			ModeRaw:       mode,
			Mode:          mode.String(),
			Path:          gadgets.FromCString(bpfEvent.Fname[:]),
			FullPath:      gadgets.FromCString(record.RawSample[unsafe.Offsetof(opensnoopEvent{}.FullFname):]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.config.FullPath = gadgetCtx.GadgetParams().Get(ParamFullPath).AsBool()
	t.config.Prefixes = gadgetCtx.GadgetParams().Get(ParamPrefixes).AsStringSlice()

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	go t.run()
	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	return nil
}

func (t *Tracer) SetMountNsMap(mountnsMap *ebpf.Map) {
	t.config.MountnsMap = mountnsMap
}

func (t *Tracer) SetEventHandler(handler any) {
	nh, ok := handler.(func(ev *types.Event))
	if !ok {
		panic("event handler invalid")
	}
	t.eventCallback = nh
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}
