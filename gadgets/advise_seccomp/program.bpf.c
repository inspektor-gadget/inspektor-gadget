// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2021 The Inspektor Gadget authors */

/* This BPF program uses the GPL-restricted function bpf_probe_read*().
 */

#include <vmlinux.h>

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include <gadget/types.h>
#include <gadget/macros.h>
#include <gadget/mntns_filter.h>

#define SYSCALLS_COUNT 500
#define SYSCALLS_MAP_VALUE_FOOTER_SIZE 1
#define SYSCALLS_MAP_VALUE_SIZE \
	(SYSCALLS_COUNT + SYSCALLS_MAP_VALUE_FOOTER_SIZE)

#define TASK_COMM_LEN 16
#define TS_COMPAT 0x0002

// prctl syscall number from
// https://github.com/seccomp/libseccomp/blob/abad8a8f41fc13efbb95fc1ccaa3e181342bade7/src/syscalls.csv#L265
#ifndef __NR_prctl
#if defined(bpf_target_x86)
#define __NR_prctl 157
#elif defined(bpf_target_arm64)
#define __NR_prctl 167
#else
#error "Unsupported architecture"
#endif
#endif

// prclt syscall parameters from
// https://github.com/torvalds/linux/blob/5147da902e0dd162c6254a61e4c57f21b60a9b1c/include/uapi/linux/prctl.h#L10
// https://github.com/torvalds/linux/blob/5147da902e0dd162c6254a61e4c57f21b60a9b1c/include/uapi/linux/prctl.h#L175
#ifndef PR_GET_PDEATHSIG
#define PR_GET_PDEATHSIG 2
#endif
#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

// Seccomp syscall number from
// https://github.com/torvalds/linux/blob/v5.12/tools/testing/selftests/seccomp/seccomp_bpf.c#L115
// Only x86_64 is supported for now.
#ifndef __NR_seccomp
#if defined(bpf_target_x86)
#define __NR_seccomp 317
#elif defined(bpf_target_arm64)
#define __NR_seccomp 277
#else
#error "Unsupported architecture"
#endif
#endif

struct key_t {
	gadget_mntns_id mntns_id_raw;
};

struct val_t {
	unsigned char syscalls[SYSCALLS_MAP_VALUE_SIZE];
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct key_t);
	__type(value, struct val_t);
	__uint(max_entries, 1024);
} syscalls_per_mntns SEC(".maps");

GADGET_MAPITER(syscalls, syscalls_per_mntns);

#ifdef __TARGET_ARCH_x86
static __always_inline int is_x86_compat(struct task_struct *task)
{
	return !!(BPF_CORE_READ(task, thread_info.status) & TS_COMPAT);
}
#endif

SEC("raw_tracepoint/sys_enter")
int ig_seccomp_e(struct bpf_raw_tracepoint_args *ctx)
{
	struct pt_regs regs = {};
	unsigned int id;
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();

	bpf_probe_read(&regs, sizeof(struct pt_regs), (void *)ctx->args[0]);
	id = ctx->args[1];

#ifdef __TARGET_ARCH_x86
	if (is_x86_compat(task)) {
		return 0;
	}
#endif

	if (id < 0 || id >= SYSCALLS_COUNT)
		return 0;

	char comm[TASK_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	int is_runc = comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' &&
			comm[3] == 'c';

	__u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0) {
		return 0;
	}

	if (gadget_should_discard_mntns_id(mntns))
		return 0;

	struct key_t key = { .mntns_id_raw = mntns };

	struct val_t *syscall_bitmap =
		bpf_map_lookup_elem(&syscalls_per_mntns, &mntns);
	if (syscall_bitmap == 0) {
		struct key_t zero = { .mntns_id_raw = 0 };
		struct val_t *blank_bitmap =
			bpf_map_lookup_elem(&syscalls_per_mntns, &zero);
		if (blank_bitmap == 0) {
			bpf_printk("blank bitmap not found");
			return 0;
		}
		bpf_map_update_elem(&syscalls_per_mntns, &key, blank_bitmap,
							BPF_NOEXIST);

		syscall_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &key);
		if (syscall_bitmap == 0)
			return 0;
	}

	// If it is runc, we want to record only the syscalls executed after the
	// seccomp profile is actually installed. However, if we are running the
	// seccomp-advisor gadget, it is very probably that the pod does not have
	// a seccomp profile yet, so seccomp() will not be called. Therefore, we
	// decide to start recording from the prctl(PR_GET_PDEATHSIG) call on. It
	// is a safe place right before all the seccomp() calls that will be always
	// executed during the runc initialisation:
	// https://github.com/opencontainers/runc/blob/8b4a8f093d0dbdf45100597f710d16777845ee83/libcontainer/standard_init_linux.go#L148
	if (is_runc) {
		if (syscall_bitmap->syscalls[SYSCALLS_COUNT] == 0) {
			if (id == __NR_prctl &&
				PT_REGS_PARM1(&regs) == PR_GET_PDEATHSIG) {
				// Start recording the runc syscalls from now on.
				syscall_bitmap->syscalls[SYSCALLS_COUNT] = 1;
			}
			return 0;
		}

		// Record all the runc syscalls after prctl(PR_GET_PDEATHSIG) except
		// for seccomp() and prctl(PR_SET_NO_NEW_PRIVS) because we know they
		// are executed before the seccomp profile is installed.
		if ((id == __NR_prctl &&
			PT_REGS_PARM1(&regs) == PR_SET_NO_NEW_PRIVS) ||
			(id == __NR_seccomp)) {
			return 0;
		}
	}

	// Record the syscall
	syscall_bitmap->syscalls[id] = 0x01;

	return 0;
}

char _license[] SEC("license") = "GPL";
