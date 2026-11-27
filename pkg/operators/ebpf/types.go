// Copyright 2024-2025 The Inspektor Gadget authors
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

package ebpfoperator

// Legacy "___"-style magic-global name prefixes.
//
// These are the ORIGINAL encoding of gadget metadata: the macros used to emit
// specially named global symbols (e.g. gadget_param_<name>, gadget_tracer_<...>)
// that the analyze() prefix walk decodes. As of the decl-tag migration the
// public macros instead emit ig:* btf_decl_tags (see include/gadget/macros.h and
// pkg/operators/ebpf/migtags.go), so newly built gadgets no longer carry these
// symbols.
//
// Deprecated: for NEW gadgets, prefer the ig:* decl-tag encoding. These prefix
// parsers are nonetheless RETAINED PERMANENTLY (they are not "transition-only")
// so that pre-built OCI images — whose eBPF ELF carries only the "___" symbols
// and no ig:* tags — keep loading with a new ig. They run side by side with the
// decl-tag readers, per the permanent backward-compatibility guarantee. Removal,
// if ever, would be a future major release.
// Keep this aligned with include/gadget/macros.h.
const (
	// Prefix used to mark trace maps
	tracerInfoPrefix = "gadget_tracer_"

	// Prefix used to mark eBPF params
	paramPrefix = "gadget_param_"

	// Prefix used to mark snapshotters structs.
	// Deprecated: use iteratorsPrefix instead
	snapshottersPrefix = "gadget_snapshotter_"

	// Prefix used for iterators
	iteratorsPrefix = "gadget_iter_"

	// Prefix used to mark tracer map created with GADGET_TRACER_MAP() defined in
	// include/gadget/buffer.h.
	tracerMapPrefix = "gadget_map_tracer_"

	mapIterPrefix = "gadget_mapiter_"

	// Prefix used by GADGET_ITER_TARGET_MAP to bind a SEC("iter/bpf_map_elem")
	// BPF program to the map it should iterate over. Deliberately chosen so
	// it does NOT share a prefix with iteratorsPrefix ("gadget_iter_") —
	// the prefix-lookup walk in analyze() matches all overlapping prefixes,
	// so a name like "gadget_iter_target_map_..." would erroneously also be
	// consumed by populateIterators.
	iterTargetMapPrefix = "gadget_mapelem_iter_target_"

	// Prefix used by GADGET_SK_TARGET_MAP to bind an sk_skb or sk_msg program
	// to its sockmap or sockhash.
	skTargetMapPrefix = "gadget_sk_prog_target_"

	// Prefix used to mark variables used by operators
	varPrefix = "gadget_var_"

	packetFilterPrefix = "gadget_pf_"
	packetFilterParam  = "pf"
)
