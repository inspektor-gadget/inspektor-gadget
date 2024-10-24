// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2024 The Inspektor Gadget authors */
//
// Prior art: sslsniff from BCC by Adrian Lopez
// https://github.com/iovisor/bcc/blob/master/tools/sslsniff.py
//
// Prior art: sslsnoop from bpftrace by Tao Xu
// https://github.com/bpftrace/bpftrace/blob/master/tools/sslsnoop.bt
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include <gadget/buffer.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#define MAX_BUF_SIZE 8192
#define MAX_ENTRIES 8192

enum operation {
	/* libssl */
	libssl_SSL_do_handshake,
	libssl_SSL_read,
	libssl_SSL_write,

	/* libgnutls */
	libgnutls_gnutls_record_send,
	libgnutls_gnutls_record_recv,

	/* libnss */
	libnss_PR_Write,
	libnss_PR_Send,
	libnss_PR_Read,
	libnss_PR_Recv,

	/* libcrypto */
	libcrypto_rsa_ossl_public_encrypt,
	libcrypto_rsa_ossl_public_decrypt,
	libcrypto_rsa_ossl_private_encrypt,
	libcrypto_rsa_ossl_private_decrypt,
	libcrypto_RSA_sign,
	libcrypto_RSA_verify,
	libcrypto_ossl_ecdsa_sign,
	libcrypto_ossl_ecdsa_verify,
	libcrypto_ossl_ecdh_compute_key,
};

struct event {
	gadget_timestamp timestamp_raw;
	gadget_mntns_id mntns_id;

	gadget_comm comm[TASK_COMM_LEN];
	// user-space terminology for pid and tid
	gadget_pid pid;
	gadget_tid tid;
	gadget_uid uid;
	gadget_gid gid;

	enum operation operation_raw;
	u64 latency_ns;
	u32 len;
	gadget_errno error_raw;
	u8 buf[MAX_BUF_SIZE];
};

#define BASE_EVENT_SIZE ((size_t)(&((struct event *)0)->buf))
#define EVENT_SIZE(X) (BASE_EVENT_SIZE + ((size_t)(X)))

GADGET_TRACER_MAP(events, 1024 * 256);
GADGET_TRACER(ssl, events, event);

const volatile bool record_data = true;
GADGET_PARAM(record_data);

/* used for context between uprobes and uretprobes of ssl operations */
struct ssl_data {
	u64 mntns_id;
	u64 start_time;
	void *buffer;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct ssl_data); // ssl_data
} ssl_context SEC(".maps");

/* used for context between uprobes and uretprobes of libcrypto operations */
struct crypto_data {
	u64 mntns_id;
	u64 start_time;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32); // tid
	__type(value, struct crypto_data); // crypto_data
} crypto_context SEC(".maps");

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
	bpf_map_delete_elem(&ssl_context, &tid);
	bpf_map_delete_elem(&crypto_context, &tid);
	return 0;
}

static __always_inline int probe_ssl_rw_enter(struct pt_regs *ctx, void *buf)
{
	struct ssl_data ssl_data;
	u64 mntns_id;
	u32 tid;
	u64 ts;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_boot_ns();

	ssl_data.mntns_id = mntns_id;
	ssl_data.start_time = ts;
	ssl_data.buffer = buf;
	bpf_map_update_elem(&ssl_context, &tid, &ssl_data, BPF_ANY);
	return 0;
}

static __always_inline int probe_ssl_rw_exit(struct pt_regs *ctx,
					     enum operation op)
{
	struct ssl_data *ssl_data;
	int len;
	u32 buf_copy_size;
	struct event *event;
	u64 pid_tgid;
	u64 uid_gid;
	u32 pid;
	u32 tid;
	u64 ts;

	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	pid = pid_tgid >> 32;
	tid = (u32)pid_tgid;
	ts = bpf_ktime_get_boot_ns();

	len = PT_REGS_RC(ctx);
	if (len <= 0) // no data
		goto clean;

	ssl_data = bpf_map_lookup_elem(&ssl_context, &tid);
	if (!ssl_data)
		goto clean;

	buf_copy_size = len;
	// MAX_BUF_SIZE is a power of two, so &=MAX_BUF_SIZE-1 makes sure
	// buf_copy_size does not go above the upper limit
	buf_copy_size &= MAX_BUF_SIZE - 1;

	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		goto clean;

	event->mntns_id = ssl_data->mntns_id;
	event->operation_raw = op;
	event->timestamp_raw = ts;
	event->latency_ns = ts - ssl_data->start_time;
	event->pid = pid;
	event->tid = tid;
	event->uid = uid_gid;
	event->gid = uid_gid >> 32;
	event->len = len;
	event->error_raw = -PT_REGS_RC(ctx);

	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	if (!record_data || bpf_probe_read_user(&event->buf, buf_copy_size,
						(char *)ssl_data->buffer))
		buf_copy_size = 0;

	gadget_submit_buf(ctx, &events, event, EVENT_SIZE(buf_copy_size));

clean:
	bpf_map_delete_elem(&ssl_context, &tid);
	return 0;
}

#define PROBE_SSL_RW_ENTER(lib, func)                                       \
	SEC("uprobe/" #lib ":" #func)                                       \
	int trace_uprobe_##lib##_##func(struct pt_regs *ctx)                \
	{                                                                   \
		return probe_ssl_rw_enter(ctx, (void *)PT_REGS_PARM2(ctx)); \
	}

#define PROBE_SSL_RW_EXIT(lib, func)                            \
	SEC("uretprobe/" #lib ":" #func)                        \
	int trace_uretprobe_##lib##_##func(struct pt_regs *ctx) \
	{                                                       \
		return probe_ssl_rw_exit(ctx, lib##_##func);    \
	}

/* uprobes for libssl */
PROBE_SSL_RW_ENTER(libssl, SSL_write)
PROBE_SSL_RW_EXIT(libssl, SSL_write)

PROBE_SSL_RW_ENTER(libssl, SSL_read)
PROBE_SSL_RW_EXIT(libssl, SSL_read)

SEC("uprobe/libssl:SSL_do_handshake")
int trace_uprobe_libssl_SSL_do_handshake(struct pt_regs *ctx)
{
	struct ssl_data ssl_data;
	u64 mntns_id;
	u32 tid;
	u64 ts;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_boot_ns();

	ssl_data.mntns_id = mntns_id;
	ssl_data.start_time = ts;
	ssl_data.buffer = NULL;
	bpf_map_update_elem(&ssl_context, &tid, &ssl_data, BPF_ANY);
	return 0;
}

SEC("uretprobe/libssl:SSL_do_handshake")
int trace_uretprobe_libssl_SSL_do_handshake(struct pt_regs *ctx)
{
	struct event *event;
	struct ssl_data *ssl_data;
	u64 pid_tgid;
	u64 uid_gid;
	u32 tid;
	u64 ts;
	int ret;

	ts = bpf_ktime_get_boot_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	tid = (u32)pid_tgid;

	ssl_data = bpf_map_lookup_elem(&ssl_context, &tid);
	if (!ssl_data)
		goto clean;

	ret = PT_REGS_RC(ctx);
	if (ret <= 0) // handshake failed
		goto clean;

	event = gadget_reserve_buf(&events, BASE_EVENT_SIZE);
	if (!event)
		goto clean;

	event->mntns_id = ssl_data->mntns_id;
	event->operation_raw = libssl_SSL_do_handshake;
	event->timestamp_raw = ts;
	event->latency_ns = ts - ssl_data->start_time;
	event->pid = pid_tgid >> 32;
	event->tid = tid;
	event->uid = uid_gid;
	event->gid = uid_gid >> 32;
	event->len = 0;
	event->error_raw = -PT_REGS_RC(ctx);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, BASE_EVENT_SIZE);

clean:
	bpf_map_delete_elem(&ssl_context, &tid);
	return 0;
}

/* uprobes for libgnutls */
PROBE_SSL_RW_ENTER(libgnutls, gnutls_record_send)
PROBE_SSL_RW_EXIT(libgnutls, gnutls_record_send)

PROBE_SSL_RW_ENTER(libgnutls, gnutls_record_recv)
PROBE_SSL_RW_EXIT(libgnutls, gnutls_record_recv)

/* uprobes for libnss */
PROBE_SSL_RW_ENTER(libnss, PR_Write)
PROBE_SSL_RW_EXIT(libnss, PR_Write)

PROBE_SSL_RW_ENTER(libnss, PR_Send)
PROBE_SSL_RW_EXIT(libnss, PR_Send)

PROBE_SSL_RW_ENTER(libnss, PR_Read)
PROBE_SSL_RW_EXIT(libnss, PR_Read)

PROBE_SSL_RW_ENTER(libnss, PR_Recv)
PROBE_SSL_RW_EXIT(libnss, PR_Recv)

/* uprobes for libcrypto */
static __always_inline int probe_crypto_enter(struct pt_regs *ctx)
{
	struct crypto_data crypto_data;
	u64 mntns_id;
	u32 tid;
	u64 ts;

	mntns_id = gadget_get_mntns_id();
	if (gadget_should_discard_mntns_id(mntns_id))
		return 0;

	tid = (u32)bpf_get_current_pid_tgid();
	ts = bpf_ktime_get_boot_ns();

	crypto_data.mntns_id = mntns_id;
	crypto_data.start_time = ts;
	bpf_map_update_elem(&crypto_context, &tid, &crypto_data, BPF_ANY);
	return 0;
}

static __always_inline int probe_crypto_exit(struct pt_regs *ctx,
					     enum operation op)
{
	struct event *event;
	struct crypto_data *crypto_data;
	u64 *mntns_ptr;
	u64 pid_tgid;
	u64 uid_gid;
	u32 tid;
	u64 ts;
	u64 *tsp;

	ts = bpf_ktime_get_boot_ns();
	pid_tgid = bpf_get_current_pid_tgid();
	uid_gid = bpf_get_current_uid_gid();
	tid = (u32)pid_tgid;

	crypto_data = bpf_map_lookup_elem(&crypto_context, &tid);
	if (!crypto_data)
		goto clean;

	event = gadget_reserve_buf(&events, BASE_EVENT_SIZE);
	if (!event)
		goto clean;

	event->mntns_id = crypto_data->mntns_id;
	event->operation_raw = op;
	event->timestamp_raw = ts;
	event->latency_ns = ts - crypto_data->start_time;
	event->pid = pid_tgid >> 32;
	event->tid = tid;
	event->uid = uid_gid;
	event->gid = uid_gid >> 32;
	event->len = 0;
	event->error_raw = -PT_REGS_RC(ctx);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	gadget_submit_buf(ctx, &events, event, BASE_EVENT_SIZE);

clean:
	bpf_map_delete_elem(&crypto_context, &tid);
	return 0;
}

#define PROBE_CRYPTO_ENTER(func)                               \
	SEC("uprobe/libcrypto:" #func)                         \
	int trace_uprobe_libcrypto_##func(struct pt_regs *ctx) \
	{                                                      \
		return probe_crypto_enter(ctx);                \
	}

#define PROBE_CRYPTO_EXIT(func)                                   \
	SEC("uprobe/libcrypto:" #func)                            \
	int trace_uretprobe_libcrypto_##func(struct pt_regs *ctx) \
	{                                                         \
		return probe_crypto_exit(ctx, libcrypto_##func);  \
	}

PROBE_CRYPTO_ENTER(rsa_ossl_public_encrypt)
PROBE_CRYPTO_EXIT(rsa_ossl_public_encrypt)

PROBE_CRYPTO_ENTER(rsa_ossl_public_decrypt)
PROBE_CRYPTO_EXIT(rsa_ossl_public_decrypt)

PROBE_CRYPTO_ENTER(rsa_ossl_private_encrypt)
PROBE_CRYPTO_EXIT(rsa_ossl_private_encrypt)

PROBE_CRYPTO_ENTER(rsa_ossl_private_decrypt)
PROBE_CRYPTO_EXIT(rsa_ossl_private_decrypt)

PROBE_CRYPTO_ENTER(RSA_sign)
PROBE_CRYPTO_EXIT(RSA_sign)

PROBE_CRYPTO_ENTER(RSA_verify)
PROBE_CRYPTO_EXIT(RSA_verify)

PROBE_CRYPTO_ENTER(ossl_ecdsa_sign)
PROBE_CRYPTO_EXIT(ossl_ecdsa_sign)

PROBE_CRYPTO_ENTER(ossl_ecdsa_verify)
PROBE_CRYPTO_EXIT(ossl_ecdsa_verify)

PROBE_CRYPTO_ENTER(ossl_ecdh_compute_key)
PROBE_CRYPTO_EXIT(ossl_ecdh_compute_key)

char LICENSE[] SEC("license") = "Dual BSD/GPL";
