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
	"github.com/syndtr/gocapability/capability"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/syscalls"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target ${TARGET} -cc clang -cflags ${CFLAGS} -type cap_event capabilities ./bpf/capable.bpf.c -- -I./bpf/

type Config struct {
	MountnsMap *ebpf.Map
	AuditOnly  bool
	Unique     bool
}

type Tracer struct {
	config        *Config
	objs          capabilitiesObjects
	capEnterLink  link.Link
	capExitLink   link.Link
	tpSysEnter    link.Link
	tpSysExit     link.Link
	tpSchedExec   link.Link
	tpSchedExit   link.Link
	reader        *perf.Reader
	enricher      gadgets.DataEnricherByMntNs
	eventCallback func(*types.Event)
}

var capabilitiesNames = map[int32]string{
	0:  "CHOWN",
	1:  "DAC_OVERRIDE",
	2:  "DAC_READ_SEARCH",
	3:  "FOWNER",
	4:  "FSETID",
	5:  "KILL",
	6:  "SETGID",
	7:  "SETUID",
	8:  "SETPCAP",
	9:  "LINUX_IMMUTABLE",
	10: "NET_BIND_SERVICE",
	11: "NET_BROADCAST",
	12: "NET_ADMIN",
	13: "NET_RAW",
	14: "IPC_LOCK",
	15: "IPC_OWNER",
	16: "SYS_MODULE",
	17: "SYS_RAWIO",
	18: "SYS_CHROOT",
	19: "SYS_PTRACE",
	20: "SYS_PACCT",
	21: "SYS_ADMIN",
	22: "SYS_BOOT",
	23: "SYS_NICE",
	24: "SYS_RESOURCE",
	25: "SYS_TIME",
	26: "SYS_TTY_CONFIG",
	27: "MKNOD",
	28: "LEASE",
	29: "AUDIT_WRITE",
	30: "AUDIT_CONTROL",
	31: "SETFCAP",
	32: "MAC_OVERRIDE",
	33: "MAC_ADMIN",
	34: "SYSLOG",
	35: "WAKE_ALARM",
	36: "BLOCK_SUSPEND",
	37: "AUDIT_READ",
	38: "PERFMON",
	39: "BPF",
	40: "CHECKPOINT_RESTORE",
}

func NewTracer(c *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*types.Event),
) (*Tracer, error) {
	t := &Tracer{
		config:        c,
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
	t.capEnterLink = gadgets.CloseLink(t.capEnterLink)
	t.capExitLink = gadgets.CloseLink(t.capExitLink)
	t.tpSysEnter = gadgets.CloseLink(t.tpSysEnter)
	t.tpSysExit = gadgets.CloseLink(t.tpSysExit)
	t.tpSchedExec = gadgets.CloseLink(t.tpSchedExec)
	t.tpSchedExit = gadgets.CloseLink(t.tpSchedExit)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadCapabilities()
	if err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	consts := map[string]interface{}{
		"audit_only": t.config.AuditOnly,
		"unique":     t.config.Unique,
	}

	if err := gadgets.LoadeBPFSpec(t.config.MountnsMap, spec, consts, &t.objs); err != nil {
		return fmt.Errorf("loading ebpf spec: %w", err)
	}

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: t.objs.IgCapSysEnter,
	})
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.tpSysEnter = tp

	tp, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: t.objs.IgCapSysExit,
	})
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.tpSysEnter = tp

	tp, err = link.Tracepoint("sched", "sched_process_exec", t.objs.IgCapSchedExec, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.tpSchedExec = tp

	tp, err = link.Tracepoint("sched", "sched_process_exit", t.objs.IgCapSchedExit, nil)
	if err != nil {
		return fmt.Errorf("attaching tracepoint: %w", err)
	}
	t.tpSchedExit = tp

	kprobe, err := link.Kprobe("cap_capable", t.objs.IgTraceCapE, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.capEnterLink = kprobe

	kretprobe, err := link.Kretprobe("cap_capable", t.objs.IgTraceCapX, nil)
	if err != nil {
		return fmt.Errorf("attaching kretprobe: %w", err)
	}
	t.capExitLink = kretprobe

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

func capsNames(capsBitField uint64) (ret []string) {
	// Ensure ret is not nil
	ret = []string{}
	for i := capability.Cap(0); i <= capability.CAP_LAST_CAP; i++ {
		if (1<<uint(i))&capsBitField != 0 {
			ret = append(ret, i.String())
		}
	}
	return
}

func boolPointer(b bool) *bool {
	return &b
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

		if len(record.RawSample) < 1 {
			t.eventCallback(types.Base(eventtypes.Warn("empty record")))
			continue
		}

		bpfEvent := (*capabilitiesCapEvent)(unsafe.Pointer(&record.RawSample[0]))

		capability := bpfEvent.Cap
		capabilityName, ok := capabilitiesNames[capability]
		if !ok {
			// If this is printed it may mean a new capability was added to the kernel
			// and capabilitiesNames map needs to be updated.
			capabilityName = fmt.Sprintf("UNKNOWN (%d)", capability)
		}

		verdict := "Deny"
		if bpfEvent.Ret == 0 {
			verdict = "Allow"
		}

		syscall, ok := syscalls.GetSyscallNameByNumber(int(bpfEvent.Syscall))
		if !ok {
			syscall = fmt.Sprintf("syscall%d", int(bpfEvent.Syscall))
		}

		var insetID *bool
		if bpfEvent.Insetid == 0 {
			insetID = boolPointer(false)
		} else if bpfEvent.Insetid > 0 {
			insetID = boolPointer(true)
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.Mntnsid},
			TargetUserNs:  bpfEvent.TargetUserns,
			CurrentUserNs: bpfEvent.CurrentUserns,
			Pid:           bpfEvent.Tgid,
			Cap:           int(bpfEvent.Cap),
			Uid:           bpfEvent.Uid,
			Gid:           bpfEvent.Gid,
			Audit:         int(bpfEvent.Audit),
			InsetID:       insetID,
			Comm:          gadgets.FromCString(bpfEvent.Task[:]),
			Syscall:       syscall,
			CapName:       capabilityName,
			Verdict:       verdict,
			Caps:          bpfEvent.CapEffective,
			CapsNames:     capsNames(bpfEvent.CapEffective),
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
	t.config.Unique = params.Get(ParamUnique).AsBool()
	t.config.AuditOnly = params.Get(ParamAuditOnly).AsBool()

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
