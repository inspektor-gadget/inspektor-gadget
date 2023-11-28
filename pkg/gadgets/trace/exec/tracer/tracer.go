// Copyright 2019-2023 The Inspektor Gadget authors
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
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/exec/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type event execsnoop ./bpf/execsnoop.bpf.c -- -I./bpf/
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type event execsnoopWithCwd ./bpf/execsnoop.bpf.c -- -DWITH_CWD -I./bpf/

type Config struct {
	MountnsMap   *ebpf.Map
	GetCwd       bool
	IgnoreErrors bool
}

type Tracer struct {
	config        *Config
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)

	objs      execsnoopObjects
	enterLink link.Link
	exitLink  link.Link
	reader    *perf.Reader
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
	t.enterLink = gadgets.CloseLink(t.enterLink)
	t.exitLink = gadgets.CloseLink(t.exitLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	var spec *ebpf.CollectionSpec
	var err error

	if t.config.GetCwd {
		spec, err = loadExecsnoopWithCwd()
	} else {
		spec, err = loadExecsnoop()
	}
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"ignore_failed": t.config.IgnoreErrors,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	t.enterLink, err = link.Tracepoint("syscalls", "sys_enter_execve", t.objs.IgExecveE, nil)
	if err != nil {
		return fmt.Errorf("attaching enter tracepoint: %w", err)
	}

	t.exitLink, err = loadExecsnoopExitLink(t.objs)
	if err != nil {
		return fmt.Errorf("attaching exit tracepoint: %w", err)
	}

	reader, err := perf.NewReader(t.objs.execsnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf ring buffer: %w", err)
	}
	t.reader = reader

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

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		if record.LostSamples > 0 {
			msg := fmt.Sprintf("lost %d samples", record.LostSamples)
			t.eventCallback(types.Base(eventtypes.Warn(msg)))
			continue
		}

		// this works regardless the kind of event because cwd is defined at the end of the
		// structure. (Just before args that are handled in a different way below)
		bpfEvent := (*execsnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			Pid:           bpfEvent.Pid,
			Ppid:          bpfEvent.Ppid,
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			LoginUid:      bpfEvent.Loginuid,
			SessionId:     bpfEvent.Sessionid,
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Retval:        int(bpfEvent.Retval),
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
		}

		argsCount := 0
		buf := []byte{}
		args := bpfEvent.Args

		if t.config.GetCwd {
			bpfEventWithCwd := (*execsnoopWithCwdEvent)(unsafe.Pointer(&record.RawSample[0]))
			event.Cwd = gadgets.FromCString(bpfEventWithCwd.Cwd[:])
			args = bpfEventWithCwd.Args
		}

		for i := 0; i < int(bpfEvent.ArgsSize) && argsCount < int(bpfEvent.ArgsCount); i++ {
			c := args[i]
			if c == 0 {
				event.Args = append(event.Args, string(buf))
				argsCount = 0
				buf = []byte{}
			} else {
				buf = append(buf, c)
			}
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	t.config.GetCwd = gadgetCtx.GadgetParams().Get(ParamCwd).AsBool()
	t.config.IgnoreErrors = gadgetCtx.GadgetParams().Get(ParamIgnoreErrors).AsBool()

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
