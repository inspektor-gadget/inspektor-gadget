// Copyright 2019-2021 The Inspektor Gadget authors
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
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// CloseLink closes l if it's not nil and returns nil
func CloseLink(l link.Link) link.Link {
	if l != nil {
		l.Close()
	}
	return nil
}

// DataEnricherByMntNs is used to enrich events with Kubernetes information,
// like node, namespace, pod name and container name when the mount namespace
// is available.
type DataEnricherByMntNs interface {
	EnrichByMntNs(event *types.CommonData, mountnsid uint64)
}

// DataNodeEnricher is used to enrich events with Kubernetes node, without
// needing any namespace.
type DataNodeEnricher interface {
	EnrichNode(event *types.CommonData)
}

// DataEnricherByNetNs is used to enrich events with Kubernetes information,
// like node, namespace, pod name and container name when the network namespace
// is available.
type DataEnricherByNetNs interface {
	EnrichByNetNs(event *types.CommonData, netnsid uint64)
}

func FromCString(in []byte) string {
	for i := 0; i < len(in); i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in)
}

func FromCStringN(in []byte, length int) string {
	l := len(in)
	if length < l {
		l = length
	}

	for i := 0; i < l; i++ {
		if in[i] == 0 {
			return string(in[:i])
		}
	}
	return string(in[:l])
}

func Htonl(hl uint32) uint32 {
	var nl [4]byte
	binary.BigEndian.PutUint32(nl[:], hl)
	return *(*uint32)(unsafe.Pointer(&nl[0]))
}

func Htons(hs uint16) uint16 {
	var ns [2]byte
	binary.BigEndian.PutUint16(ns[:], hs)
	return *(*uint16)(unsafe.Pointer(&ns[0]))
}

func IPStringFromBytes(ipBytes [16]byte, ipType int) string {
	switch ipType {
	case 4:
		return netip.AddrFrom4(*(*[4]byte)(ipBytes[0:4])).String()
	case 6:
		return netip.AddrFrom16(ipBytes).String()
	default:
		return ""
	}
}

// IPStringToByteArray converts an IP address (IPv6 only) string to a uint32
// in big-endian.
func IPStringToByteArray(ipAddr string) ([16]byte, error) {
	addr, err := netip.ParseAddr(ipAddr)
	if err != nil {
		return [16]byte{}, fmt.Errorf("invalid IP address: %s", ipAddr)
	}

	if !addr.Is6() {
		return [16]byte{}, fmt.Errorf("IP address is not IPv6: %s", addr)
	}

	// This function ensures us the order is big endian:
	// https://cs.opensource.google/go/go/+/refs/tags/go1.20.5:src/net/netip/netip.go;drc=dc98ccd836da7d22a5d270b9778fb055826fa07b;l=676
	return addr.As16(), nil
}

// IPStringToUint32 converts an IP address (IPv4 only) string to a uint32
// in big-endian.
func IPStringToUint32(ipAddr string) (uint32, error) {
	// Notice ipAddr is already expressed in big-endian and net.ParseIP stores
	// it in a byte array in big-endian too.
	ip := net.ParseIP(ipAddr).To4()
	if ip == nil {
		return 0, fmt.Errorf("invalid IP address: %s", ipAddr)
	}
	// Convert the byte array to a uint32 keeping the big-endian order. We don't
	// use binary.[BigEndian|LittleEndian].Uint32() to make this code portable.
	return *(*uint32)(unsafe.Pointer(&ip[0])), nil
}

func IPVerFromAF(af uint16) int {
	switch af {
	case unix.AF_INET:
		return 4
	case unix.AF_INET6:
		return 6
	default:
		return 0
	}
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

var (
	bpfKtimeGetBootNsOnce   sync.Once
	bpfKtimeGetBootNsExists bool
)

// DetectBpfKtimeGetBootNs returns true if bpf_ktime_get_boot_ns is available
// in the current kernel. False negatives are possible if BTF is not available.
func DetectBpfKtimeGetBootNs() bool {
	bpfKtimeGetBootNsOnce.Do(func() {
		bpfKtimeGetBootNsExists = false

		btfSpec, err := btf.LoadKernelSpec()
		if err != nil {
			return
		}

		enum := &btf.Enum{}
		err = btfSpec.TypeByName("bpf_func_id", &enum)
		if err != nil {
			return
		}

		for _, value := range enum.Values {
			if value.Name == "BPF_FUNC_ktime_get_boot_ns" && value.Value == BpfKtimeGetBootNsFuncID {
				bpfKtimeGetBootNsExists = true

				return
			}
		}
	})

	return bpfKtimeGetBootNsExists
}

// removeBpfKtimeGetBootNs removes calls to bpf_ktime_get_boot_ns and replaces
// it by an assignment to zero
func removeBpfKtimeGetBootNs(p *ebpf.ProgramSpec) {
	iter := p.Instructions.Iterate()

	for iter.Next() {
		in := iter.Ins

		if in.OpCode.Class().IsJump() &&
			in.OpCode.JumpOp() == asm.Call &&
			in.Constant == BpfKtimeGetBootNsFuncID {
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
	if DetectBpfKtimeGetBootNs() {
		return
	}

	for _, s := range programSpecs {
		removeBpfKtimeGetBootNs(s)
	}
}

// LoadeBPFSpec is a helper to load an eBPF spec from gadgets.
// It replaces filter map and calls the necessary functions to load
// Maps and Programs into the kernel
func LoadeBPFSpec(
	mountnsMap *ebpf.Map,
	spec *ebpf.CollectionSpec,
	consts map[string]interface{},
	objs interface{},
) error {
	FixBpfKtimeGetBootNs(spec.Programs)

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if mountnsMap != nil {
		filterByMntNs = true
		mapReplacements[MntNsFilterMapName] = mountnsMap
	}

	if consts == nil {
		consts = map[string]interface{}{}
	}

	consts[FilterByMntNsName] = filterByMntNs

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}

	if err := spec.LoadAndAssign(objs, &opts); err != nil {
		return fmt.Errorf("loading maps and programs: %w", err)
	}

	return nil
}
