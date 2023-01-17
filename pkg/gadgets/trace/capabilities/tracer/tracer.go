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
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	libseccomp "github.com/seccomp/libseccomp-golang"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/trace/capabilities/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -type cap_event capabilities ./bpf/capable.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap *ebpf.Map
	AuditOnly  bool
	Unique     bool
}

type Tracer struct {
	config               *Config
	objs                 capabilitiesObjects
	capEnterLink         link.Link
	capExitLink          link.Link
	tpSysEnter           link.Link
	tpSysExit            link.Link
	reader               *perf.Reader
	enricher             gadgets.DataEnricherByMntNs
	eventCallback        func(*types.Event)
	runningKernelVersion uint32
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

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	t.capEnterLink = gadgets.CloseLink(t.capEnterLink)
	t.capExitLink = gadgets.CloseLink(t.capExitLink)
	t.tpSysEnter = gadgets.CloseLink(t.tpSysEnter)
	t.tpSysExit = gadgets.CloseLink(t.tpSysExit)

	if t.reader != nil {
		t.reader.Close()
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	runningKernelVersion, err := features.LinuxVersionCode()
	if err != nil {
		return fmt.Errorf("error getting kernel version: %w", err)
	}
	t.runningKernelVersion = runningKernelVersion

	spec, err := loadCapabilities()
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

	consts := map[string]interface{}{
		"filter_by_mnt_ns":   filterByMntNs,
		"linux_version_code": runningKernelVersion,
		"audit_only":         t.config.AuditOnly,
		"unique":             t.config.Unique,
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

	tp, err := link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_enter",
		Program: t.objs.IgCapSysEnter,
	})
	if err != nil {
		return fmt.Errorf("failed to open tracepoint: %w", err)
	}
	t.tpSysEnter = tp

	tp, err = link.AttachRawTracepoint(link.RawTracepointOptions{
		Name:    "sys_exit",
		Program: t.objs.IgCapSysExit,
	})
	if err != nil {
		return fmt.Errorf("failed to open tracepoint: %w", err)
	}
	t.tpSysEnter = tp

	kprobe, err := link.Kprobe("cap_capable", t.objs.IgTraceCapE, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.capEnterLink = kprobe

	kretprobe, err := link.Kretprobe("cap_capable", t.objs.IgTraceCapX, nil)
	if err != nil {
		return fmt.Errorf("error opening kretprobe: %w", err)
	}
	t.capExitLink = kretprobe

	reader, err := perf.NewReader(t.objs.capabilitiesMaps.Events, gadgets.PerfBufferPages*os.Getpagesize())
	if err != nil {
		return fmt.Errorf("error creating perf ring buffer: %w", err)
	}
	t.reader = reader

	go t.run()

	return nil
}

// kernelVersion returns a uint32 corresponding to the kernel version.
// This function is go translation of KERNEL_VERSION macro:
// https://elixir.bootlin.com/linux/v5.18/source/tools/lib/bpf/bpf_helpers.h#L61
func kernelVersion(a, b, c int) uint32 {
	if c > 255 {
		c = 255
	}

	return uint32((a << 16) + (b << 8) + c)
}

func (t *Tracer) run() {
	for {
		record, err := t.reader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}

			msg := fmt.Sprintf("Error reading perf ring buffer: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg)))
			return
		}

		bpfEvent := (*capabilitiesCapEvent)(unsafe.Pointer(&record.RawSample[0]))

		capability := bpfEvent.Cap
		capabilityName, ok := capabilitiesNames[capability]
		if !ok {
			// If this is printed it may mean a new capability was added to the kernel
			// and capabilitiesNames map needs to be updated.
			capabilityName = fmt.Sprintf("UNKNOWN (%d)", capability)
		}

		capOpt := int(bpfEvent.CapOpt)

		var audit int
		true_ := true
		false_ := false
		var insetID *bool

		if t.runningKernelVersion >= kernelVersion(5, 1, 0) {
			audit = 0
			if (capOpt & 0b10) == 0 {
				audit = 1
			}

			insetID = &false_
			if (capOpt & 0b100) != 0 {
				insetID = &true_
			}
		} else {
			audit = capOpt
		}

		verdict := "Deny"
		if bpfEvent.Ret == 0 {
			verdict = "Allow"
		}

		syscall := ""
		call1 := libseccomp.ScmpSyscall(bpfEvent.Syscall)
		if name, err := call1.GetName(); err == nil {
			syscall = name
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type:      eventtypes.NORMAL,
				Timestamp: gadgets.WallTimeFromBootTime(bpfEvent.Timestamp),
			},
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: bpfEvent.Mntnsid},
			Pid:           bpfEvent.Pid,
			Cap:           int(bpfEvent.Cap),
			UID:           bpfEvent.Uid,
			Audit:         audit,
			InsetID:       insetID,
			Comm:          gadgets.FromCString(bpfEvent.Task[:]),
			Syscall:       syscall,
			CapName:       capabilityName,
			Verdict:       verdict,
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

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{},
	}
	return tracer, nil
}

func (t *Tracer) Init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.Unique = params.Get(ParamUnique).AsBool()
	t.config.AuditOnly = params.Get(ParamAuditOnly).AsBool()
	return nil
}
