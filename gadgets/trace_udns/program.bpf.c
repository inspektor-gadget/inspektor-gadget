// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>
#include <gadget/types.h>

#define AF_INET 2
#define AF_INET6 10

enum op {
	getaddrinfo,
	gethostbyname,
	gethostbyname2,
};

// Max DNS name length: 255
// https://datatracker.ietf.org/doc/html/rfc1034#section-3.1
#define MAX_DNS_NAME 255

struct event {
	gadget_mntns_id mntns_id;
	__u32 pid;
	__u32 tid;
	__u8 comm[TASK_COMM_LEN];
	enum op operation;
	__u8 name[MAX_DNS_NAME];
	__u8 service[MAX_DNS_NAME];
	struct gadget_l3endpoint_t endpoint;
};

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(udns, events, event);

// struct addrinfo comes from netdb.h in glibc or musl:
// https://sourceware.org/git/?p=glibc.git;a=blob;f=resolv/netdb.h;hb=ded2e0753e9c46debeb2e0d26c5e560d2581d314#l565
// https://git.etalabs.net/cgit/musl/tree/include/netdb.h#n16
struct addrinfo {
	int ai_flags;
	int ai_family;
	int ai_socktype;
	int ai_protocol;
	__u32 ai_addrlen;
	struct sockaddr *ai_addr;
	char *ai_canonname;
	struct addrinfo *ai_next;
};

struct lookup {
	const char *node;
	const char *service;
	const void *hints;
	const struct addrinfo **res;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32); // tid
	__type(value, struct lookup);
} lookups SEC(".maps");

SEC("uprobe/libc:getaddrinfo")
int BPF_KPROBE(getaddrinfo_e, const char *node, const char *service,
	       const void *hints, const struct addrinfo **res)

{
	u64 mntns_id;
	u64 pid_tgid;
	u32 tid;
	struct lookup lookup = {};

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	tid = (__u32)pid_tgid;

	lookup.node = node;
	lookup.service = service;
	lookup.hints = hints;
	lookup.res = res;

	bpf_map_update_elem(&lookups, &tid, &lookup, BPF_ANY);

	return 0;
}

SEC("uretprobe/libc:getaddrinfo")
int BPF_KRETPROBE(getaddrinfo_x, int ret)
{
	struct event *event;
	u64 mntns_id;
	u64 pid_tgid;
	u32 pid, tid;
	struct lookup *lookup;
	struct addrinfo *result;
	int ai_family;
	struct sockaddr_in *addr;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (__u32)pid_tgid;

	lookup = bpf_map_lookup_elem(&lookups, &tid);
	if (!lookup)
		return 0;

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = mntns_id;
	event->pid = pid;
	event->tid = tid;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation = getaddrinfo;
	bpf_probe_read_user_str(event->name, sizeof(event->name), lookup->node);
	bpf_probe_read_user_str(event->service, sizeof(event->service),
				lookup->service);

	bpf_probe_read_user(&result, sizeof(result), lookup->res);
	bpf_probe_read_user(&ai_family, sizeof(ai_family), &result->ai_family);
	if (ai_family == AF_INET) {
		event->endpoint.version = 4;
		bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);
		bpf_probe_read_user(&event->endpoint.addr.v4,
				    sizeof(event->endpoint.addr.v4),
				    &addr->sin_addr);
	} else if (ai_family == AF_INET6) {
		event->endpoint.version = 6;
		bpf_probe_read_user(&addr, sizeof(addr), &result->ai_addr);
		bpf_probe_read_user(&event->endpoint.addr.v6,
				    sizeof(event->endpoint.addr.v6),
				    &addr->sin_addr);
	}

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
