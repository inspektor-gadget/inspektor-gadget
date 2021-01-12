// +build ignore
// ^^ this is a golang build tag meant to exclude this C file from compilation by the CGO compiler

/* In Linux 5.4 asm_inline was introduced, but it's not supported by clang.
 * Redefine it to just asm to enable successful compilation.
 * see https://github.com/iovisor/bcc/commit/2d1497cde1cc9835f759a707b42dea83bee378b8 for more details
 */
#include <linux/types.h>
#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/mm_types.h>
#include <linux/mount.h>
#include <linux/nsproxy.h>
#include <linux/ns_common.h>
#include <linux/pid_namespace.h>
#include <linux/security.h>
#include <linux/socket.h>
#include <linux/version.h>

#include <uapi/linux/bpf.h>
#include <linux/kconfig.h>
#include <linux/version.h>

#undef container_of
//#include "bpf_core_read.h"
#include <bpf_helpers.h>
#include <bpf_tracing.h>

/* Idea from https://github.com/iovisor/bcc
 *
 * XXX: struct mnt_namespace is defined in fs/mount.h, which is private
 * to the VFS and not installed in any kernel-devel packages. So, let's
 * duplicate the important part of the definition. There are actually
 * more members in the real struct, but we don't need them, and they're
 * more likely to change.
 */
struct mnt_namespace {
    atomic_t count;
    struct ns_common ns;
};

#define READ_KERN(ptr) ({ typeof(ptr) _val;                             \
                          __builtin_memset(&_val, 0, sizeof(_val));     \
                          bpf_probe_read(&_val, sizeof(_val), &ptr);    \
                          _val;                                         \
                        })

#ifndef printt
# define printt(fmt, ...)						\
	({ \
	char ____fmt[] = fmt; \
	bpf_trace_printk(____fmt, sizeof(____fmt), \
	##__VA_ARGS__); \
	})
#endif

/* Keep in sync with constants in pkg/gadgets/seccomp/advisor.go
 */
#define SYSCALLS_COUNT			500
#define SYSCALLS_MAP_VALUE_FOOTER_SIZE	1
#define SYSCALLS_MAP_VALUE_SIZE		(SYSCALLS_COUNT + SYSCALLS_MAP_VALUE_FOOTER_SIZE)

#define nr_seccomp 317
#ifndef SECCOMP_SET_MODE_FILTER
#define SECCOMP_SET_MODE_FILTER         1
#endif

struct bpf_map_def SEC("maps") syscalls_per_mntns = {
  .type = BPF_MAP_TYPE_HASH,
  .key_size = sizeof(uint64_t),
  .value_size = SYSCALLS_MAP_VALUE_SIZE,
  .max_entries = 128,
};

static __always_inline bool is_x86_compat(struct task_struct *task)
{
    return READ_KERN(task->thread_info.status) & TS_COMPAT;
}

// include/trace/events/syscalls.h:
// TP_PROTO(struct pt_regs *regs, long id)
SEC("raw_tracepoint/sys_enter")
int tracepoint__raw_syscalls__sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs regs = {};
    unsigned int id;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    bpf_probe_read(&regs, sizeof(struct pt_regs), (void*)ctx->args[0]);
    id = ctx->args[1];

    if (is_x86_compat(task)) {
        return 0;
    }

    if (id < 0 || id >= SYSCALLS_COUNT)
        return 0;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    bool is_runc = comm[0] == 'r' && comm[1] == 'u' && comm[2] == 'n' && comm[3] == 'c';

    struct nsproxy *nsproxy;
    struct mnt_namespace *mnt_ns;
    u64 mntns;
    int err;

    err = bpf_probe_read(&nsproxy, sizeof(nsproxy), (void *)&task->nsproxy);
    if (err != 0) {
        return 0;
    }

    err = bpf_probe_read(&mnt_ns, sizeof(mnt_ns), (void *)&nsproxy->mnt_ns);
    if (err != 0) {
        return 0;
    }

    err = bpf_probe_read(&mntns, sizeof(mntns), (void *)&mnt_ns->ns.inum);
    if (err != 0) {
        return 0;
    }

    if (mntns == 0) {
        return 0;
    }

    u8 *syscall_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &mntns);
    if (syscall_bitmap == NULL) {
        u64 zero = 0;
        u8 *blank_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &zero);
        if (blank_bitmap == NULL)
            return 0;
        bpf_map_update_elem(&syscalls_per_mntns, &mntns, blank_bitmap, BPF_NOEXIST);

        syscall_bitmap = bpf_map_lookup_elem(&syscalls_per_mntns, &mntns);
        if (syscall_bitmap == NULL)
            return 0;
    }

    if (is_runc) {
        /* libseccomp makes invalid calls to seccomp() to determine the api
         * level. Ignore those. */
        if (id == nr_seccomp &&
		PT_REGS_PARM1(&regs) == SECCOMP_SET_MODE_FILTER &&
		PT_REGS_PARM3(&regs) != 0) {
            /* Mark this container: seccomp has been called. */
            syscall_bitmap[SYSCALLS_COUNT] = 1;
            return 0;
        }
        /* Don't register syscalls performed by runc before the seccomp policy is actually installed */
        if (syscall_bitmap[SYSCALLS_COUNT] == 0)
            return 0;
    }

    syscall_bitmap[id] = 0x01;

    return 0;
}

char LICENSE[] SEC("license") = "GPL";
int KERNEL_VERSION SEC("version") = LINUX_VERSION_CODE;
