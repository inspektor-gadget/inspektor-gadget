/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef __PROFILE_H
#define __PROFILE_H

#define TASK_COMM_LEN		16
#define MAX_CPU_NR		128
#define MAX_ENTRIES		10240

struct key_t {
	__u64 kernel_ip;
	__u64 mntns_id;
	__u32 pid;
	int user_stack_id;
	int kern_stack_id;
	__u8 name[TASK_COMM_LEN];
};

#endif /* __PROFILE_H */
