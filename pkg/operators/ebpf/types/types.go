// Copyright 2024 The Inspektor Gadget authors
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

// Package types contains the names and Golang representation of the types used
// by the eBPF programs. Keep this aligned with include/gadget/types.h
package types

const (
	IPAddrTypeName      = "gadget_ip_addr_t"
	L3EndpointTypeName  = "gadget_l3endpoint_t"
	L4EndpointTypeName  = "gadget_l4endpoint_t"
	MntNsTypeName       = "gadget_mntns_id"
	NetNsTypeName       = "gadget_netns_id"
	TimestampTypeName   = "gadget_timestamp"
	SignalTypeName      = "gadget_signal"
	ErrnoTypeName       = "gadget_errno"
	UidTypeName         = "gadget_uid"
	GidTypeName         = "gadget_gid"
	KernelStackTypeName = "gadget_kernel_stack"
	PidTypeName         = "gadget_pid"
	PpidTypeName        = "gadget_ppid"
	TidTypeName         = "gadget_tid"
	CommTypeName        = "gadget_comm"
	PcommTypeName       = "gadget_pcomm"
	SyscallTypeName     = "gadget_syscall"

	// Metrics
	CounterU32TypeName       = "gadget_counter__u32"
	CounterU64TypeName       = "gadget_counter__u64"
	GaugeU32TypeName         = "gadget_gauge__u32"
	GaugeU64TypeName         = "gadget_gauge__u64"
	HistogramSlotU32TypeName = "gadget_histogram_slot__u32"
	HistogramSlotU64TypeName = "gadget_histogram_slot__u64"
)

// L3Endpoint is the Golang representation of struct gadget_l3endpoint_t
type L3Endpoint struct {
	V6      [16]byte
	Version uint8
	_       [3]byte
}
