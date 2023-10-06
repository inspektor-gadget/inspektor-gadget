// Copyright 2023 The Inspektor Gadget authors
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

package gadgets

const (
	PinPath = "/sys/fs/bpf/gadget"

	// The Trace custom resource is preferably in the "gadget" namespace
	TraceDefaultNamespace = "gadget"

	PerfBufferPages = 64

	// bpf_ktime_get_boot_ns()'s func id as defined in Linux API
	// https://github.com/torvalds/linux/blob/v6.2-rc1/include/uapi/linux/bpf.h#L5614
	BpfKtimeGetBootNsFuncID = 125

	// Constant used to enable filtering by mount namespace inode id in eBPF.
	// Keep in syn with variable defined in pkg/gadgets/common/mntns_filter.h.
	FilterByMntNsName = "gadget_filter_by_mntns"

	// Name of the map that stores the mount namespace inode id to filter on.
	// Keep in syn with name used in pkg/gadgets/common/mntns_filter.h.
	MntNsFilterMapName = "gadget_mntns_filter_map"

	// Name of the type that gadgets should use to store an L3 endpoint.
	// Keep in sync with pkg/gadgets/common/types.h
	L3EndpointTypeName = "gadget_l3endpoint_t"

	// Name of the type that gadgets should use to store an L4 endpoint.
	// Keep in sync with pkg/gadgets/common/types.h
	L4EndpointTypeName = "gadget_l4endpoint_t"

	// Name of the type to store a mount namespace inode id
	MntNsIdTypeName = "mnt_ns_id_t"

	// Prefix used to mark trace maps
	TraceMapPrefix = "gadget_trace_map_"
)
