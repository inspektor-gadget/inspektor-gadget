//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
// SPDX-License-Identifier: Apache-2.0

package tracer

// #include <linux/types.h>
// #include "./bpf/sigsnoop.h"
import "C"

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
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/sigsnoop/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/sigsnoop/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"

	"golang.org/x/sys/unix"
)

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang sigsnoop ./bpf/sigsnoop.bpf.c -- -I../../../.. -target bpf -D__TARGET_ARCH_x86"

type Tracer struct {
	config *tracer.Config

	objs               sigsnoopObjects
	enterKillLink      link.Link
	exitKillLink       link.Link
	enterTkillLink     link.Link
	exitTkillLink      link.Link
	enterTgkillLink    link.Link
	exitTgkillLink     link.Link
	signalGenerateLink link.Link
	reader             *perf.Reader

	resolver      containercollection.ContainerResolver
	eventCallback func(types.Event)
	node          string
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

func signalIntToString(signal int) string {
	return unix.SignalName(syscall.Signal(signal))
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
	t.enterKillLink = gadgets.CloseLink(t.enterKillLink)
	t.exitKillLink = gadgets.CloseLink(t.exitKillLink)

	t.enterTkillLink = gadgets.CloseLink(t.enterTkillLink)
	t.exitTkillLink = gadgets.CloseLink(t.exitTkillLink)

	t.enterTgkillLink = gadgets.CloseLink(t.enterTgkillLink)
	t.exitTgkillLink = gadgets.CloseLink(t.exitTgkillLink)

	t.signalGenerateLink = gadgets.CloseLink(t.signalGenerateLink)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadSigsnoop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
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

	t.enterKillLink, err = link.Tracepoint("syscalls", "sys_enter_kill", t.objs.KillEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.exitKillLink, err = link.Tracepoint("syscalls", "sys_exit_kill", t.objs.KillExit, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.enterTkillLink, err = link.Tracepoint("syscalls", "sys_enter_tkill", t.objs.TkillEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.exitTkillLink, err = link.Tracepoint("syscalls", "sys_exit_tkill", t.objs.TkillExit, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.enterTgkillLink, err = link.Tracepoint("syscalls", "sys_enter_tgkill", t.objs.TgkillEntry, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.exitTgkillLink, err = link.Tracepoint("syscalls", "sys_exit_tgkill", t.objs.TgkillExit, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
	}

	t.signalGenerateLink, err = link.Tracepoint("signal", "signal_generate", t.objs.SigTrace, nil)
	if err != nil {
		return fmt.Errorf("error opening tracepoint: %w", err)
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
			Pid:       uint32(eventC.pid),
			TargetPid: uint32(eventC.tpid),
			Signal:    signalIntToString(int(eventC.sig)),
			Retval:    int(eventC.ret),
			MountNsID: uint64(eventC.mntns_id),
			Comm:      C.GoString(&eventC.comm[0]),
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
