// SPDX-License-Identifier: Apache-2.0
/* Copyright (c) 2024 The Inspektor Gadget authors */
//
// Based on sslsnoop from bpftrace by Tao Xu
// https://github.com/bpftrace/bpftrace/blob/master/tools/sslsnoop.bt
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

/* The maximum number of items in maps */
#define MAX_ENTRIES 8192

enum function {
	SSL_read,
	SSL_write,
	SSL_do_handshake,

	rsa_ossl_public_encrypt,
	rsa_ossl_public_decrypt,
	rsa_ossl_private_encrypt,
	rsa_ossl_private_decrypt,
	RSA_sign,
	RSA_verify,
	ossl_ecdsa_sign,
	ossl_ecdsa_verify,
	ossl_ecdh_compute_key,
};

struct event {
	gadget_mntns_id mntns_id;
	__u64 time;
	__u32 pid;
	__u32 tid;
	__u8 comm[TASK_COMM_LEN];
	enum function operation;
	__u64 retval;
	__u64 latency_us;
};

/* used for context between uprobes and uretprobes of libssl operations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64); // start_time
} start_ssl SEC(".maps");

/* used for context between uprobes and uretprobes of libcrypto operations */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, u64); // start_time
} start_crypto SEC(".maps");

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(sslsnoop, events, event);

/**
 * clean up the maps when a thread terminates,
 * because there may be residual data in the map
 * if a userspace thread is killed between a uprobe and a uretprobe
 */
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_process_exit(void *ctx)
{
	u32 tid;

	tid = (u32)bpf_get_current_pid_tgid();
	bpf_map_delete_elem(&start_ssl, &tid);
	return 0;
}

static __always_inline int record_start_time(struct pt_regs *ctx,
					     enum function operation)
{
	u64 mntns_id;
	u64 start_time;
	u32 tid;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	start_time = bpf_ktime_get_ns();
	tid = (u32)bpf_get_current_pid_tgid();

	switch (operation) {
	case SSL_read:
	case SSL_write:
	case SSL_do_handshake:
		bpf_map_update_elem(&start_ssl, &tid, &start_time, BPF_ANY);
		break;
	default:
		bpf_map_update_elem(&start_crypto, &tid, &start_time, BPF_ANY);
		break;
	}
	return 0;
}

static __always_inline int submit_event(struct pt_regs *ctx,
					enum function operation, u64 retval)
{
	u64 mntns_id;
	struct event *event;
	u64 pid_tgid;
	u32 pid;
	u32 tid;
	u64 current_time;
	u64 start_time;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	current_time = bpf_ktime_get_ns();

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;
	tid = (u32)pid_tgid;

	switch (operation) {
	case SSL_read:
	case SSL_write:
	case SSL_do_handshake: {
		u64 *start_time_ptr = bpf_map_lookup_elem(&start_ssl, &tid);
		if (!start_time_ptr)
			return 0;
		start_time = *start_time_ptr;
		bpf_map_delete_elem(&start_ssl, &tid);
		break;
	}
	default: {
		u64 *start_time_ptr = bpf_map_lookup_elem(&start_crypto, &tid);
		if (!start_time_ptr)
			return 0;
		start_time = *start_time_ptr;
		bpf_map_delete_elem(&start_crypto, &tid);
		break;
	}
	}

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		return 0;

	event->mntns_id = mntns_id;
	event->time = current_time;
	event->pid = pid;
	event->tid = tid;
	bpf_get_current_comm(event->comm, sizeof(event->comm));
	event->operation = operation;
	event->retval = retval;
	event->latency_us = (current_time - start_time) / 1000;

	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	return 0;
}

/* uprobes for libssl */
#define RECORD_START_TIME_FOR_LIBSSL(func)                  \
	SEC("uprobe/libssl:" #func)                         \
	int trace_uprobe_libssl_##func(struct pt_regs *ctx) \
	{                                                   \
		return record_start_time(ctx, func);        \
	}

#define SUBMIT_EVENT_FOR_LIBSSL(func)                            \
	SEC("uretprobe/libssl:" #func)                           \
	int trace_uretprobe_libssl_##func(struct pt_regs *ctx)   \
	{                                                        \
		return submit_event(ctx, func, PT_REGS_RC(ctx)); \
	}

RECORD_START_TIME_FOR_LIBSSL(SSL_read)
RECORD_START_TIME_FOR_LIBSSL(SSL_write)
RECORD_START_TIME_FOR_LIBSSL(SSL_do_handshake)

SUBMIT_EVENT_FOR_LIBSSL(SSL_read)
SUBMIT_EVENT_FOR_LIBSSL(SSL_write)
SUBMIT_EVENT_FOR_LIBSSL(SSL_do_handshake)

/* uprobes for libcrypto */
#define RECORD_START_TIME_FOR_LIBCRYPTO(func)                  \
	SEC("uprobe/libcrypto:" #func)                         \
	int trace_uprobe_libcrypto_##func(struct pt_regs *ctx) \
	{                                                      \
		return record_start_time(ctx, func);           \
	}

#define SUBMIT_EVENT_FOR_LIBCRYPTO(func)                          \
	SEC("uretprobe/libcrypto:" #func)                         \
	int trace_uretprobe_libcrypto_##func(struct pt_regs *ctx) \
	{                                                         \
		return record_start_time(ctx, func);              \
	}

RECORD_START_TIME_FOR_LIBCRYPTO(rsa_ossl_public_encrypt)
RECORD_START_TIME_FOR_LIBCRYPTO(rsa_ossl_public_decrypt)
RECORD_START_TIME_FOR_LIBCRYPTO(rsa_ossl_private_encrypt)
RECORD_START_TIME_FOR_LIBCRYPTO(rsa_ossl_private_decrypt)
RECORD_START_TIME_FOR_LIBCRYPTO(RSA_sign)
RECORD_START_TIME_FOR_LIBCRYPTO(RSA_verify)
RECORD_START_TIME_FOR_LIBCRYPTO(ossl_ecdsa_sign)
RECORD_START_TIME_FOR_LIBCRYPTO(ossl_ecdsa_verify)
RECORD_START_TIME_FOR_LIBCRYPTO(ossl_ecdh_compute_key)

SUBMIT_EVENT_FOR_LIBCRYPTO(rsa_ossl_public_encrypt)
SUBMIT_EVENT_FOR_LIBCRYPTO(rsa_ossl_public_decrypt)
SUBMIT_EVENT_FOR_LIBCRYPTO(rsa_ossl_private_encrypt)
SUBMIT_EVENT_FOR_LIBCRYPTO(rsa_ossl_private_decrypt)
SUBMIT_EVENT_FOR_LIBCRYPTO(RSA_sign)
SUBMIT_EVENT_FOR_LIBCRYPTO(RSA_verify)
SUBMIT_EVENT_FOR_LIBCRYPTO(ossl_ecdsa_sign)
SUBMIT_EVENT_FOR_LIBCRYPTO(ossl_ecdsa_verify)
SUBMIT_EVENT_FOR_LIBCRYPTO(ossl_ecdh_compute_key)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
