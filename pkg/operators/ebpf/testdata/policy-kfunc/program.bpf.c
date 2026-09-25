// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
// Copyright 2026 The Inspektor Gadget authors

#define SEC(name) __attribute__((section(name), used))

extern void bpf_rcu_read_lock(void) __attribute__((section(".ksyms")));
extern void bpf_rcu_read_unlock(void) __attribute__((section(".ksyms")));

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int observe(void *ctx)
{
	bpf_rcu_read_lock();
	bpf_rcu_read_unlock();
	return 0;
}

char LICENSE[] SEC("license") = "GPL";
