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


#include <linux/kconfig.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wgnu-variable-sized-type-not-at-end"
#pragma clang diagnostic ignored "-Waddress-of-packed-member"
#include <linux/ptrace.h>
#pragma clang diagnostic pop
#include <linux/version.h>
#include <linux/bpf.h>
#include "bpf_helpers.h"

#define PIN_CUSTOM_NS 3

/* This is a key/value store with the keys being the cgroupid
 * and the values are ignored.
 */
struct bpf_map_def SEC("maps/cgroupid_set") cgroupid_set = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u32),
	.max_entries = 128,
	.pinning = PIN_CUSTOM_NS,
	.namespace = "gadget-tracers",
};

/* This is a key/value store with the keys being the mntns
 * and the values are ignored.
 */
struct bpf_map_def SEC("maps/mntns_set") mntns_set = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(__u64),
	.value_size = sizeof(__u32),
	.max_entries = 10240,
	.pinning = PIN_CUSTOM_NS,
	.namespace = "gadget-tracers",
};
