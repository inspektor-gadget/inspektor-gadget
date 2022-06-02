// SPDX-License-Identifier: GPL-2.0
//
// Unique filtering based on
// https://github.com/libbpf/libbpf-rs/tree/master/examples/capable
//
// Copyright 2022 Sony Group Corporation

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "capable.h"

#define MAX_ENTRIES	10240

extern int LINUX_KERNEL_VERSION __kconfig;

const volatile pid_t my_pid = -1;
const volatile enum uniqueness unique_type = UNQ_OFF;
const volatile bool kernel_stack = false;
const volatile bool user_stack = false;
const volatile bool filter_cg = false;
const volatile pid_t targ_pid = -1;

struct unique_key {
	int cap;
	u32 tgid;
	u64 cgroupid;
};

struct {
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(__u32));
	__uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
} stackmap SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct cap_event);
	__uint(max_entries, MAX_ENTRIES);
} info SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 10240);
	__type(key, struct unique_key);
	__type(value, u64);
} seen SEC(".maps");

SEC("kprobe/cap_capable")
int BPF_KPROBE(kprobe__cap_capable, const struct cred *cred, struct user_namespace *targ_ns, int cap, int cap_opt)
{
	__u32 pid;
	__u64 pid_tgid;
	struct key_t i_key;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	pid_tgid = bpf_get_current_pid_tgid();
	pid = pid_tgid >> 32;

	if (pid == my_pid)
		return 0;

	if (targ_pid != -1 && targ_pid != pid)
		return 0;

	struct cap_event event = {};
	event.pid = pid;
	event.tgid = pid_tgid;
	event.cap = cap;
	event.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&event.task, sizeof(event.task));

	if (LINUX_KERNEL_VERSION >= KERNEL_VERSION(5, 1, 0)) {
		/* @opts: Bitmask of options defined in include/linux/security.h */
		event.audit = (cap_opt & 0b10) == 0;
		event.insetid = (cap_opt & 0b100) != 0;
	} else {
		event.audit = cap_opt;
		event.insetid = -1;
	}

	if (unique_type) {
		struct unique_key key = {.cap = cap};
		if (unique_type == UNQ_CGROUP) {
			key.cgroupid = bpf_get_current_cgroup_id();
		} else {
			key.tgid = pid_tgid;
		}

		if (bpf_map_lookup_elem(&seen, &key) != NULL) {
			return 0;
		}
		u64 zero = 0;
		bpf_map_update_elem(&seen, &key, &zero, 0);
	}

	if (kernel_stack || user_stack) {
		i_key.pid = pid;
		i_key.tgid = pid_tgid;

		if (kernel_stack && user_stack) {
			i_key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
			i_key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
		} else if (user_stack) {
			i_key.user_stack_id = bpf_get_stackid(ctx, &stackmap, BPF_F_USER_STACK);
			i_key.kern_stack_id = -1;
		} else if (kernel_stack) {
			i_key.kern_stack_id = bpf_get_stackid(ctx, &stackmap, 0);
			i_key.user_stack_id = -1;
		}

		bpf_map_update_elem(&info, &i_key, &event, BPF_NOEXIST);
	}
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
