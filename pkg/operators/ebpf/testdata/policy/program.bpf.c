// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
// Copyright 2026 The Inspektor Gadget authors

#define SEC(name) __attribute__((section(name), used))

static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;

static __attribute__((noinline)) unsigned long long read_pid(void)
{
	return bpf_get_current_pid_tgid();
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int observe(void *ctx)
{
	return read_pid() & 1;
}

char LICENSE[] SEC("license") = "GPL";
