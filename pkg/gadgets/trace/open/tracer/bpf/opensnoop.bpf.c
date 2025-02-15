// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <gadget/mntns_filter.h>
#include <gadget/filesystem.h>
#include "opensnoop.h"

#define NR_MAX_PREFIX_FILTER 255
#define CHAR_BIT 8

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = INVALID_UID;
const volatile bool targ_failed = false;
const volatile bool get_full_path = false;
const volatile __u32 prefixes_nr = 0;

// we need this to make sure the compiler doesn't remove our struct
const struct event *unusedevent __attribute__((unused));

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, u32);
	__type(value, struct start_t);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LPM_TRIE);
	__type(key, struct prefix_key);
	__type(value, __u8);
	__uint(map_flags, BPF_F_NO_PREALLOC);
	__uint(max_entries, NR_MAX_PREFIX_FILTER);
} prefixes SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, u32);
	__type(value, struct prefix_key);
} prefix_keys SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct event);
} empty_event SEC(".maps");

static const struct prefix_key empty_prefix_key = {};

static __always_inline bool valid_uid(uid_t uid)
{
	return uid != INVALID_UID;
}

static __always_inline bool trace_allowed(u32 tgid, u32 pid,
					  const char *filename)
{
	u64 mntns_id;
	u32 uid;

	/* filters */
	if (targ_tgid && targ_tgid != tgid)
		return false;
	if (targ_pid && targ_pid != pid)
		return false;
	if (valid_uid(targ_uid)) {
		uid = (u32)bpf_get_current_uid_gid();
		if (targ_uid != uid) {
			return false;
		}
	}

	if (prefixes_nr) {
		struct prefix_key *key;
		bool found;

		found = false;

		/*
		 * Allocate prefix_key from map rather than stack to avoid
		 * hitting the verifier limit.
		 */
		if (bpf_map_update_elem(&prefix_keys, &pid, &empty_prefix_key,
					BPF_NOEXIST))
			goto clean;

		key = bpf_map_lookup_elem(&prefix_keys, &pid);
		if (!key)
			goto clean;

		/*
		 * It is fine to give the whole buffer size as prefixlen here.
		 * Indeed, the in-kernel lookup stops when there is a difference
		 * between the node (i.e. tested prefix) and the key (i.e.
		 * filename).
		 * There will always be a difference if the filename is longer
		 * than the prefix, but what matters is the matched length.
		 * If it equals the prefix length, then the filename matches the
		 * prefix.
		 */
		key->prefixlen = sizeof(key->filename) * CHAR_BIT;
		__builtin_memcpy(key->filename, filename,
				 sizeof(key->filename));

		found = bpf_map_lookup_elem(&prefixes, key) != NULL;
clean:
		bpf_map_delete_elem(&prefix_keys, &pid);
		if (!found)
			return false;
	}

	mntns_id = gadget_get_current_mntns_id();

	if (gadget_should_discard_mntns_id(mntns_id))
		return false;

	return true;
}

static __always_inline int trace_enter(const char *filename, int flags,
				       __u16 mode)
{
	u64 id = bpf_get_current_pid_tgid();
	/* use kernel terminology here for tgid/pid: */
	u32 tgid = id >> 32;
	u32 pid = id;

	struct start_t s = {};

	bpf_probe_read_user_str(s.fname, sizeof(s.fname), filename);

	/* store arg info for later lookup */
	if (!trace_allowed(tgid, pid, (const char *)s.fname))
		return 0;

	s.flags = flags;
	s.mode = mode;

	// TODO: not related to this commit. Should't it be id? instead of pid?
	bpf_map_update_elem(&start, &pid, &s, BPF_ANY);

	return 0;
}

SEC("tracepoint/syscalls/sys_enter_open")
int ig_open_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[0], (int)ctx->args[1],
			   (__u16)ctx->args[2]);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int ig_openat_e(struct syscall_trace_enter *ctx)
{
	return trace_enter((const char *)ctx->args[1], (int)ctx->args[2],
			   (__u16)ctx->args[3]);
}

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	struct event *event;
	long int ret;
	__u32 fd;
	__s32 errval;
	u32 pid = bpf_get_current_pid_tgid();
	u64 uid_gid = bpf_get_current_uid_gid();
	u64 mntns_id;
	size_t full_fname_len = 0;
	struct start_t *s;

	s = bpf_map_lookup_elem(&start, &pid);
	if (!s)
		return 0; /* missed entry */

	u32 zero = 0;
	event = bpf_map_lookup_elem(&empty_event, &zero);
	if (!event)
		return 0; // should never happen

	event->flags = s->flags;
	event->mode = s->mode;
	__builtin_memcpy(event->fname, s->fname, sizeof(s->fname));

	ret = ctx->ret;
	if (targ_failed && ret >= 0)
		goto cleanup; /* want failed only */

	fd = 0;
	errval = 0;
	if (ret >= 0) {
		fd = ret;
	} else {
		errval = -ret;
	}

	u64 pid_tgid = bpf_get_current_pid_tgid();
	/* event data */
	event->pid = pid_tgid >> 32;
	event->tid = pid_tgid & 0xffffffff;
	event->uid = (u32)uid_gid;
	event->gid = (u32)(uid_gid >> 32);
	bpf_get_current_comm(&event->comm, sizeof(event->comm));
	event->err = errval;
	event->fd = fd;
	event->mntns_id = gadget_get_current_mntns_id();
	event->timestamp = bpf_ktime_get_boot_ns();

	// Attempting to extract the full file path with symlink resolution
	if (ret >= 0 && get_full_path) {
		long r = read_full_path_of_open_file_fd(
			ret, (char *)event->full_fname,
			sizeof(event->full_fname));
		if (r > 0) {
			full_fname_len = (size_t)r;
		} else {
			// If we cannot get the full path put the empty string
			event->full_fname[0] = '\0';
			full_fname_len = 1;
		}
	} else {
		// If the open failed, we can't get the full path
		event->full_fname[0] = '\0';
		full_fname_len = 1;
	}

	__u64 event_size;
	const size_t base_event_size = sizeof(struct event);
	const size_t path_adjustment = PATH_MAX - full_fname_len;

	// Ensure we don't underflow when calculating the adjusted size
	if (full_fname_len <= PATH_MAX) {
		event_size = base_event_size - path_adjustment;
	} else {
		event_size = base_event_size;
	}

	/* emit event */
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event,
			      event_size);
cleanup:
	bpf_map_delete_elem(&start, &pid);
	return 0;
}

SEC("tracepoint/syscalls/sys_exit_open")
int ig_open_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int ig_openat_x(struct syscall_trace_exit *ctx)
{
	return trace_exit(ctx);
}

char LICENSE[] SEC("license") = "GPL";
