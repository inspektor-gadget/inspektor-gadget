// Copyright 2022-2023 The Inspektor Gadget authors
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
	"os"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/fsslower/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -cc clang -cflags ${CFLAGS} -type event fsslower ./bpf/fsslower.bpf.c -- -I./bpf/
type Config struct {
	MountnsMap *ebpf.Map

	Filesystem string
	MinLatency uint
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs            fsslowerObjects
	readEnterLink   link.Link
	readExitLink    link.Link
	writeEnterLink  link.Link
	writeExitLink   link.Link
	openEnterLink   link.Link
	openExitLink    link.Link
	syncEnterLink   link.Link
	syncExitLink    link.Link
	statfsEnterLink link.Link
	statfsExitLink  link.Link
	reader          *perf.Reader
}

type fsConf struct {
	read   string
	write  string
	open   string
	fsync  string
	statfs string
}

var fsConfMap = map[string]fsConf{
	"btrfs": {
		read:   "btrfs_file_read_iter",
		write:  "btrfs_file_write_iter",
		open:   "btrfs_file_open",
		fsync:  "btrfs_sync_file",
		statfs: "btrfs_statfs",
	},
	"ext4": {
		read:   "ext4_file_read_iter",
		write:  "ext4_file_write_iter",
		open:   "ext4_file_open",
		fsync:  "ext4_sync_file",
		statfs: "ext4_statfs",
	},
	"fuse": {
		read:  "fuse_file_read_iter",
		write: "fuse_file_write_iter",
		open:  "fuse_open",
		fsync: "fuse_fsync",
	},
	"nfs": {
		read:   "nfs_file_read",
		write:  "nfs_file_write",
		open:   "nfs_file_open",
		fsync:  "nfs_file_fsync",
		statfs: "nfs_statfs",
	},
	"ntfs3": {
		read:  "ntfs_file_read_iter",
		write: "ntfs_file_write_iter",
		open:  "ntfs_file_open",
		fsync: "generic_file_fsync",
	},
	"xfs": {
		read:   "xfs_file_read_iter",
		write:  "xfs_file_write_iter",
		open:   "xfs_file_open",
		fsync:  "xfs_file_fsync",
		statfs: "xfs_fs_statfs",
	},
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

	// statfs
	t.statfsEnterLink = gadgets.CloseLink(t.statfsEnterLink)
	t.statfsExitLink = gadgets.CloseLink(t.statfsExitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var err error

	spec, err := loadFsslower()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"min_lat_ns": uint64(t.config.MinLatency * 1000 * 1000),
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	// choose a configuration based on the filesystem type passed
	fsConf, ok := fsConfMap[t.config.Filesystem]
	if !ok {
		return fmt.Errorf("%q is not a supported filesystem", t.config.Filesystem)
	}

	// read
	t.readEnterLink, err = link.Kprobe(fsConf.read, t.objs.IgFsslReadE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.readExitLink, err = link.Kretprobe(fsConf.read, t.objs.IgFsslReadX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}

	// write
	t.writeEnterLink, err = link.Kprobe(fsConf.write, t.objs.IgFsslWrE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.writeExitLink, err = link.Kretprobe(fsConf.write, t.objs.IgFsslWrX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}

	// open
	t.openEnterLink, err = link.Kprobe(fsConf.open, t.objs.IgFsslOpenE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.openExitLink, err = link.Kretprobe(fsConf.open, t.objs.IgFsslOpenX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}

	// sync
	t.syncEnterLink, err = link.Kprobe(fsConf.fsync, t.objs.IgFsslSyncE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.syncExitLink, err = link.Kretprobe(fsConf.fsync, t.objs.IgFsslSyncX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}

	// statfs
	t.statfsEnterLink, err = link.Kprobe(fsConf.statfs, t.objs.IgFsslStatfsE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.statfsExitLink, err = link.Kretprobe(fsConf.statfs, t.objs.IgFsslStatfsX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}

	t.reader, err = perf.NewReader(t.objs.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	if err := gadgets.FreezeMaps(t.objs.Events); err != nil {
		return err
	}

	return nil
}

var ops = []string{"R", "W", "O", "F", "S"}

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

		bpfEvent := (*fsslowerEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Comm:          gadgets.FromCString(bpfEvent.Task[:]),
			Pid:           bpfEvent.Pid,
			Op:            ops[int(bpfEvent.Op)],
			Bytes:         bpfEvent.Size,
			Offset:        bpfEvent.Offset,
			Latency:       bpfEvent.DeltaUs,
			File:          gadgets.FromCString(bpfEvent.File[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.Filesystem = params.Get(ParamFilesystem).AsString()
	t.config.MinLatency = params.Get(ParamMinLatency).AsUint()

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
