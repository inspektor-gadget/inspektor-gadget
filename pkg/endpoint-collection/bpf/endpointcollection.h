/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0 */

#ifndef ENDPOINT_COLLECTION_H
#define ENDPOINT_COLLECTION_H

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

const volatile __u32 current_endpoint_id = 0;

struct endpoints_key {
	struct bpf_lpm_trie_key key;
	__u32	ip;
};

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__uint(max_entries, 10240);
	__type(key, struct endpoints_key); // int + IPv4
	__type(value, __u64); // id
	__uint(map_flags, BPF_F_NO_PREALLOC);
} endpoints SEC(".maps");

static __always_inline __u64
gadget_endpoint_lookup(__u32 ip)
{
	__u32 key[2];
	key[0] = 32;
	key[1] = ip;

	__u64 *id = bpf_map_lookup_elem(&endpoints, &key);
	if (!id)
		return 0;
	return *id;
}

#endif
