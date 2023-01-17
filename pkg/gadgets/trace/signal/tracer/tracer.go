//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package tracer

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/signal/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"

	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -type event sigsnoop ./bpf/sigsnoop.bpf.c -- -I../../../../${TARGET}

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

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
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

func (t *Tracer) start() error {
	spec, err := loadSigsnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	gadgets.FixBpfKtimeGetBootNs(spec.Programs)

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = t.config.MountnsMap
	}

	signal, err := signalStringToInt(t.config.TargetSignal)
	if err != nil {
		return fmt.Errorf("cannot translate signal (%q) to int: %w", t.config.TargetSignal, err)
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
		"filtered_pid":     t.config.TargetPid,
		"target_signal":    signal,
		"failed_only":      t.config.FailedOnly,
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

	if t.config.KillOnly {
		t.enterKillLink, err = link.Tracepoint("syscalls", "sys_enter_kill", t.objs.IgSigKillE, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_enter_kill: %w", err)
		}

		t.exitKillLink, err = link.Tracepoint("syscalls", "sys_exit_kill", t.objs.IgSigKillX, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_exit_kill: %w", err)
		}

		t.enterTkillLink, err = link.Tracepoint("syscalls", "sys_enter_tkill", t.objs.IgSigTkillE, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_enter_tkill: %w", err)
		}

		t.exitTkillLink, err = link.Tracepoint("syscalls", "sys_exit_tkill", t.objs.IgSigTkillX, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_exit_tkill: %w", err)
		}

		t.enterTgkillLink, err = link.Tracepoint("syscalls", "sys_enter_tgkill", t.objs.IgSigTgkillE, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_enter_tgkill: %w", err)
		}

		t.exitTgkillLink, err = link.Tracepoint("syscalls", "sys_exit_tgkill", t.objs.IgSigTgkillX, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint sys_exit_tgkill: %w", err)
		}
	} else {
		t.signalGenerateLink, err = link.Tracepoint("signal", "signal_generate", t.objs.IgSigGenerate, nil)
		if err != nil {
			return fmt.Errorf("error opening tracepoint signal_generate: %w", err)
		}
	}

	t.reader, err = perf.NewReader(t.objs.sigsnoopMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}

	go t.run()

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

		bpfEvent := (*sigsnoopEvent)(unsafe.Pointer(&record.RawSample[0]))

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			Pid:       bpfEvent.Pid,
			TargetPid: bpfEvent.Tpid,
			Signal:    signalIntToString(int(bpfEvent.Sig)),
			Retval:    int(bpfEvent.Ret),
			MountNsID: bpfEvent.MntnsId,
			Comm:      gadgets.FromCString(bpfEvent.Comm[:]),
		}

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&event.CommonData, event.MountNsID)
		}

		t.eventCallback(&event)
	}
}

// --- Registry changes

func (t *Tracer) Start() error {
	if err := t.start(); err != nil {
		t.Stop()
		return err
	}
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

func (g *Gadget) NewInstance(runner gadgets.Runner) (gadgets.GadgetInstance, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	if runner == nil {
		return tracer, nil
	}

	params := runner.GadgetParams()
	tracer.config.TargetPid = params.Get(ParamPID).AsInt32()
	tracer.config.FailedOnly = params.Get(ParamFailedOnly).AsBool()
	tracer.config.KillOnly = params.Get(ParamKillOnly).AsBool()
	tracer.config.TargetSignal = params.Get(ParamTargetSignal).AsString()
	return tracer, nil
}
