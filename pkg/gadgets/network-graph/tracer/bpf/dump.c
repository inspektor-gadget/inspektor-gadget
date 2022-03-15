// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2022 The Inspektor Gadget authors */

// Avoid CO-RE:
// CO-RE relocations: relocate struct#35["iphdr"]: target struct#49626["iphdr"]: target struct#49626["iphdr"]: field "ihl" is a bitfield: not supported 
// 
// #include <vmlinux/vmlinux.h>

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/in.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

#include "graph.h"

#include "graphmap.h"

struct bpf_iter_meta {
	__bpf_md_ptr(struct seq_file *, seq);
	__u64 session_id;
	__u64 seq_num;
};

struct bpf_iter__bpf_map_elem {
	__bpf_md_ptr(struct bpf_iter_meta *, meta);
	__bpf_md_ptr(struct bpf_map *, map);
	__bpf_md_ptr(void *, key);
	__bpf_md_ptr(void *, value);
};

/* From: tools/lib/bpf/bpf_tracing.h */
/*
 * BPF_SEQ_PRINTF to wrap bpf_seq_printf to-be-printed values
 * in a structure.
 */
#define BPF_SEQ_PRINTF(seq, fmt, args...)                                  \
       ({                                                                  \
               _Pragma("GCC diagnostic push")                              \
               _Pragma("GCC diagnostic ignored \"-Wint-conversion\"")      \
               static const char ___fmt[] = fmt;                           \
               unsigned long long ___param[] = { args };                   \
               _Pragma("GCC diagnostic pop")                               \
               int ___ret = bpf_seq_printf(seq, ___fmt, sizeof(___fmt),    \
                                           ___param, sizeof(___param));    \
               ___ret;                                                     \
       })


SEC("iter/bpf_map_elem")
int dump_graph(struct bpf_iter__bpf_map_elem *ctx)
{
	struct seq_file *seq = ctx->meta->seq;
	__u32 seq_num = ctx->meta->seq_num;
	struct bpf_map *map = ctx->map;
	struct graph_key_t *key = ctx->key;
	struct graph_key_t tmp_key;
	char *val = ctx->value;

	if (key == (void *)0 || val == (void *)0) {
		return 0;
	}

#ifdef SIMULATE_KERNEL_WITHOUT_BPF_ITERATORS
	for (;;);
#endif

	BPF_SEQ_PRINTF(seq, "%u %u %u %u ",
		key->container_quark,
		key->pkt_type,
		key->proto,
		bpf_htons(key->port));
	BPF_SEQ_PRINTF(seq, "%pI4\n", &key->ip);

	__builtin_memcpy(&tmp_key, key, sizeof(struct graph_key_t));
	bpf_map_delete_elem(&graphmap, &tmp_key);

	return 0;
}

char _license[] SEC("license") = "GPL";
