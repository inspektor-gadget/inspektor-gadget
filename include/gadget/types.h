/* SPDX-License-Identifier: Apache-2.0 */

#ifndef __TYPES_H
#define __TYPES_H

// The bool definition can come from vmlinux.h or stdbool.h.
#if !defined(__VMLINUX_H__)
#include <stdbool.h>
#endif

// Keep these types aligned with definitions in pkg/operators/ebpf/types/types.go.

// union defining either an IPv4 or IPv6 address
union gadget_ip_addr_t {
	__u8 v6[16];
	unsigned __int128 v6_raw;
	__u32 v4;
};

// struct defining either an IPv4 or IPv6 L3 endpoint
struct gadget_l3endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u8 version; // 4 or 6
};

// struct defining an L4 endpoint
struct gadget_l4endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u16 port; // L4 port in host byte order
	__u16 proto_raw; // IP protocol number
	__u8 version; // 4 or 6
};

// Inode id of a mount namespace. It's used to enrich the event in user space
typedef __u64 gadget_mntns_id;

// Inode id of a network namespace. It's used to enrich the event in user space
typedef __u32 gadget_netns_id;

// gadget_timestamp is a type that represents the nanoseconds since the system boot. Gadgets can use
// this type to provide a timestamp. The value contained must be the one returned by
// bpf_ktime_get_boot_ns() and it's automatically converted by Inspektor Gadget to a human friendly
// time.
typedef __u64 gadget_timestamp;

// gadget_signal is used to represent a unix signal. A field is automatically added that contains the name
// as string.
typedef __u32 gadget_signal;

// gadget_errno is used to represent a unix errno. A field is automatically added that contains the name
// as string.
typedef __u32 gadget_errno;

// gadget_uid is used to represent a uid. A field is automatically added that contains the corresponding user
// name on the host system
typedef __u32 gadget_uid;

// gadget_gid is used to represent a uid. A field is automatically added that contains the corresponding group
// name on the host system
typedef __u32 gadget_gid;

// gadget_syscall is used to represent a unix syscall. A field is automatically added that contains the name
// as string.
typedef __u64 gadget_syscall;

typedef __u32 gadget_kernel_stack;

struct gadget_user_stack {
	// Identify the executable. Leave it as 0 to disable user stacks.
	__u64 exe_inode;
	__u64 mtime_sec;
	__u32 mtime_nsec;

	// The stack id as returned by bpf_get_stackid.
	__u32 stack_id;

	// Pid number from the initial pid namespace's point of view.
	// In some setups (e.g. Minikube with Docker driver), the pidns of ig's
	// /host/proc mount is not the init pidns. To support this edge case, we
	// give the pid numbers from the level 1 pidns as well. Userspace can
	// figure out which pid to use based on the pidns.
	// Use separate fields because arrays are not supported:
	// https://github.com/inspektor-gadget/inspektor-gadget/issues/4060
	__u32 pid_level0;
	__u32 pidns_level0;
	__u32 pid_level1;
	__u32 pidns_level1;
};

#ifndef TASK_COMM_LEN
#define TASK_COMM_LEN 16
#endif

typedef __u32 gadget_pid;
typedef __u32 gadget_ppid;
typedef __u32 gadget_tid;
typedef char gadget_comm;
typedef char gadget_pcomm;
typedef __u64 gadget_bytes;
typedef __u64 gadget_duration;

// typedefs used for metrics
typedef __u32 gadget_counter__u32;
typedef __u64 gadget_counter__u64;
typedef __u32 gadget_gauge__u32;
typedef __u64 gadget_gauge__u64;
typedef __u32 gadget_histogram_slot__u32;
typedef __u64 gadget_histogram_slot__u64;

struct gadget_creds {
	gadget_uid uid;
	gadget_gid gid;
};

struct gadget_parent {
	gadget_pcomm comm[TASK_COMM_LEN];
	gadget_ppid pid;
};

struct gadget_process {
	gadget_comm comm[TASK_COMM_LEN];
	gadget_pid pid;
	gadget_tid tid;
	gadget_mntns_id mntns_id;

	struct gadget_creds creds;
	struct gadget_parent parent;
};

#define SE_PATH_MAX 512

struct sockets_value {
	__u64 mntns;
	__u64 pid_tgid;
	__u64 uid_gid;
	char task[TASK_COMM_LEN];
	char ptask[TASK_COMM_LEN];
	__u64 sock;
	__u64 deletion_timestamp;
	char cwd[SE_PATH_MAX];
	char exepath[SE_PATH_MAX];
	__u32 ppid;
	char ipv6only;
};

#endif /* __TYPES_H */
