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
	"strconv"
	"strings"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags ${CFLAGS} -type event sigsnoop ./bpf/sigsnoop.bpf.c --

type Config struct {
	MountnsMap   *ebpf.Map
	TargetSignal string
	TargetPid    int32
	FailedOnly   bool
	KillOnly     bool
}

type Tracer struct {
	config *Config

	objs               sigsnoopObjects
	enterKillLink      link.Link
	exitKillLink       link.Link
	enterTkillLink     link.Link
	exitTkillLink      link.Link
	enterTgkillLink    link.Link
	exitTgkillLink     link.Link
	signalGenerateLink link.Link
	reader             *perf.Reader

	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)
}

func signalIntToString(signal int) string {
	return unix.SignalName(syscall.Signal(signal))
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
	t.enterKillLink = gadgets.CloseLink(t.enterKillLink)
	t.exitKillLink = gadgets.CloseLink(t.exitKillLink)

	t.enterTkillLink = gadgets.CloseLink(t.enterTkillLink)
	t.exitTkillLink = gadgets.CloseLink(t.exitTkillLink)

	t.enterTgkillLink = gadgets.CloseLink(t.enterTgkillLink)
	t.exitTgkillLink = gadgets.CloseLink(t.exitTgkillLink)

	t.signalGenerateLink = gadgets.CloseLink(t.signalGenerateLink)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadSigsnoop()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	signal, err := signalStringToInt(t.config.TargetSignal)
	if err != nil {
		return fmt.Errorf("converting signal (%q) to int: %w", t.config.TargetSignal, err)
	}

	consts := map[string]interface{}{
		"filtered_pid":  t.config.TargetPid,
		"target_signal": signal,
		"failed_only":   t.config.FailedOnly,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	if t.config.KillOnly {
		t.enterKillLink, err = link.Tracepoint("syscalls", "sys_enter_kill", t.objs.IgSigKillE, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_enter_kill: %w", err)
		}

		t.exitKillLink, err = link.Tracepoint("syscalls", "sys_exit_kill", t.objs.IgSigKillX, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_exit_kill: %w", err)
		}

		t.enterTkillLink, err = link.Tracepoint("syscalls", "sys_enter_tkill", t.objs.IgSigTkillE, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_enter_tkill: %w", err)
		}

		t.exitTkillLink, err = link.Tracepoint("syscalls", "sys_exit_tkill", t.objs.IgSigTkillX, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_exit_tkill: %w", err)
		}

		t.enterTgkillLink, err = link.Tracepoint("syscalls", "sys_enter_tgkill", t.objs.IgSigTgkillE, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_enter_tgkill: %w", err)
		}

		t.exitTgkillLink, err = link.Tracepoint("syscalls", "sys_exit_tgkill", t.objs.IgSigTgkillX, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint sys_exit_tgkill: %w", err)
		}
	} else {
		t.signalGenerateLink, err = link.Tracepoint("signal", "signal_generate", t.objs.IgSigGenerate, nil)
		if err != nil {
			return fmt.Errorf("attaching tracepoint signal_generate: %w", err)
		}
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

		bpfEvent := (*sigsnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			Pid:           bpfEvent.Pid,
			TargetPid:     bpfEvent.Tpid,
			Signal:        signalIntToString(int(bpfEvent.Sig)),
			Retval:        int(bpfEvent.Ret),
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.MntnsId},
			Comm:          gadgets.FromCString(bpfEvent.Comm[:]),
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
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
	t.config.TargetPid = params.Get(ParamPID).AsInt32()
	t.config.FailedOnly = params.Get(ParamFailedOnly).AsBool()
	t.config.KillOnly = params.Get(ParamKillOnly).AsBool()
	t.config.TargetSignal = params.Get(ParamTargetSignal).AsString()

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

func signalStringToInt(signal string) (int32, error) {
	// There are three possibilities:
	// 1. Either user did not give a signal, thus the argument is empty string.
	// 2. Or signal begins with SIG.
	// 3. Or signal is a string which contains an integer.
	if signal == "" {
		return 0, nil
	}

	if strings.HasPrefix(signal, "SIG") {
		signalNum := unix.SignalNum(signal)
		if signalNum == 0 {
			return 0, fmt.Errorf("no signal found for %q", signal)
		}

		return int32(signalNum), nil
	}

	signalNum, err := strconv.ParseInt(signal, 10, 32)

	return int32(signalNum), err
}
