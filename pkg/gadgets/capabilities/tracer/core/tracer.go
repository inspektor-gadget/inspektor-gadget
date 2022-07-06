//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
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

package tracer

// #include <linux/types.h>
// #include "./bpf/capable.h"
import "C"

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/capabilities/tracer"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/capabilities/types"
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang capabilities ./bpf/capable.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Tracer struct {
	config           *tracer.Config
	objs             capabilitiesObjects
	capabilitiesLink link.Link
	reader           *perf.Reader
	resolver         containercollection.ContainerResolver
	eventCallback    func(types.Event)
	node             string
}

var capabilitiesNames = map[uint32]string{
	0:  "CAP_CHOWN",
	1:  "CAP_DAC_OVERRIDE",
	2:  "CAP_DAC_READ_SEARCH",
	3:  "CAP_FOWNER",
	4:  "CAP_FSETID",
	5:  "CAP_KILL",
	6:  "CAP_SETGID",
	7:  "CAP_SETUID",
	8:  "CAP_SETPCAP",
	9:  "CAP_LINUX_IMMUTABLE",
	10: "CAP_NET_BIND_SERVICE",
	11: "CAP_NET_BROADCAST",
	12: "CAP_NET_ADMIN",
	13: "CAP_NET_RAW",
	14: "CAP_IPC_LOCK",
	15: "CAP_IPC_OWNER",
	16: "CAP_SYS_MODULE",
	17: "CAP_SYS_RAWIO",
	18: "CAP_SYS_CHROOT",
	19: "CAP_SYS_PTRACE",
	20: "CAP_SYS_PACCT",
	21: "CAP_SYS_ADMIN",
	22: "CAP_SYS_BOOT",
	23: "CAP_SYS_NICE",
	24: "CAP_SYS_RESOURCE",
	25: "CAP_SYS_TIME",
	26: "CAP_SYS_TTY_CONFIG",
	27: "CAP_MKNOD",
	28: "CAP_LEASE",
	29: "CAP_AUDIT_WRITE",
	30: "CAP_AUDIT_CONTROL",
	31: "CAP_SETFCAP",
	32: "CAP_MAC_OVERRIDE",
	33: "CAP_MAC_ADMIN",
	34: "CAP_SYSLOG",
	35: "CAP_WAKE_ALARM",
	36: "CAP_BLOCK_SUSPEND",
	37: "CAP_AUDIT_READ",
	38: "CAP_PERFMON",
	39: "CAP_BPF",
	40: "CAP_CHECKPOINT_RESTORE",
}

func NewTracer(c *tracer.Config, resolver containercollection.ContainerResolver,
	eventCallback func(types.Event), node string,
) (*Tracer, error) {
	t := &Tracer{
		config:        c,
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
	t.capabilitiesLink = gadgets.CloseLink(t.capabilitiesLink)

	if t.reader != nil {
		t.reader.Close()
		t.reader = nil
	}

	t.objs.Close()
}

func (t *Tracer) start() error {
	spec, err := loadCapabilities()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
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

	kprobe, err := link.Kprobe("cap_capable", t.objs.KprobeCapCapable, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}
	t.capabilitiesLink = kprobe

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
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
			return
		}

		eventC := (*C.struct_cap_event)(unsafe.Pointer(&record.RawSample[0]))

		capability := uint32(eventC.cap)
		capabilityName, ok := capabilitiesNames[capability]
		if !ok {
			// If this is printed it may mean a new capability was added to the kernel
			// and capabilitiesNames map needs to be updated.
			capabilityName = fmt.Sprintf("UNKNOWN (%d)", capability)
		}

		runningKernelVersion, err := features.LinuxVersionCode()
		if err != nil {
			msg := fmt.Sprintf("Error getting kernel version: %s", err)
			t.eventCallback(types.Base(eventtypes.Err(msg, t.node)))
		}

		capOpt := int(eventC.cap_opt)

		var audit int
		var insetID int

		if runningKernelVersion >= kernelVersion(5, 1, 0) {
			audit = 0
			if (capOpt & 0b10) == 0 {
				audit = 1
			}

			insetID = 0
			if (capOpt & 0b100) != 0 {
				insetID = 1
			}
		} else {
			audit = capOpt
			insetID = -1
		}

		insetString := "N/A"
		if insetID != -1 {
			insetString = strconv.Itoa(insetID)
		}

		event := types.Event{
			Event: eventtypes.Event{
				Type: eventtypes.NORMAL,
				Node: t.node,
			},
			MountNsID: uint64(eventC.mntnsid),
			Pid:       uint32(eventC.pid),
			Cap:       int(eventC.cap),
			UID:       uint32(eventC.uid),
			Audit:     audit,
			InsetID:   insetString,
			Comm:      C.GoString(&eventC.task[0]),
			CapName:   capabilityName,
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
