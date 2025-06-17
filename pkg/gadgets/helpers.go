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

package gadgets

import (
	"fmt"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// CloseLink closes l if it's not nil and returns nil
func CloseLink(l link.Link) link.Link {
	if l != nil {
		l.Close()
	}
	return nil
}

var timeDiff time.Duration

func init() {
	var t unix.Timespec
	err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &t)
	if err != nil {
		panic(err)
	}
	timeDiff = time.Duration(time.Now().UnixNano() - t.Sec*1000*1000*1000 - t.Nsec)
}

// WallTimeFromBootTime converts a time from bpf_ktime_get_boot_ns() to the
// wall time with nano precision.
//
// Example:
//
//	fmt.Printf("Time: %s\n", WallTimeFromBootTime(ts).String())
//
// would display:
//
//	Time: 2022-12-15T16:49:00.452371948+01:00
//
// Shell command to convert the number to a date:
//
//	$ date -d @$(echo 1671447636499110634/1000000000|bc -l) +"%d-%m-%Y %H:%M:%S:%N"
//	19-12-2022 12:00:36:499110634
//
// bpf_ktime_get_boot_ns was added in Linux 5.7. If not available and the BPF
// program returns 0, just get the timestamp in userspace.
func WallTimeFromBootTime(ts uint64) types.Time {
	if ts == 0 {
		return types.Time(time.Now().UnixNano())
	}
	return types.Time(time.Unix(0, int64(ts)).Add(timeDiff).UnixNano())
}

// HasBpfKtimeGetBootNs returns true if bpf_ktime_get_boot_ns is available
func HasBpfKtimeGetBootNs() bool {
	// We only care about the helper, hence test with ebpf.SocketFilter that exist in all
	// kernels that support ebpf.
	err := features.HaveProgramHelper(ebpf.SocketFilter, asm.FnKtimeGetBootNs)
	return err == nil
}

// removeBpfKtimeGetBootNs removes calls to bpf_ktime_get_boot_ns and replaces
// it by an assignment to zero
func removeBpfKtimeGetBootNs(p *ebpf.ProgramSpec) {
	iter := p.Instructions.Iterate()

	for iter.Next() {
		in := iter.Ins

		if in.OpCode.Class().IsJump() &&
			in.OpCode.JumpOp() == asm.Call &&
			in.Constant == int64(asm.FnKtimeGetBootNs) {
			// reset timestamp to zero
			in.OpCode = asm.Mov.Op(asm.ImmSource)
			in.Dst = asm.R0
			in.Constant = 0
		}
	}
}

// FixBpfKtimeGetBootNs checks if bpf_ktime_get_boot_ns is supported by the
// kernel and removes it if not
func FixBpfKtimeGetBootNs(programSpecs map[string]*ebpf.ProgramSpec) {
	if HasBpfKtimeGetBootNs() {
		return
	}

	for _, s := range programSpecs {
		removeBpfKtimeGetBootNs(s)
	}
}

func FreezeMaps(maps ...*ebpf.Map) error {
	for _, m := range maps {
		if err := m.Freeze(); err != nil {
			if info, _ := m.Info(); info != nil {
				return fmt.Errorf("freezing map %s: %w", info.Name, err)
			}
			return fmt.Errorf("freezing map: %w", err)
		}
	}

	return nil
}
