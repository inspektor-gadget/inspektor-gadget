// SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
// Copyright 2026 The Inspektor Gadget authors

#define SEC(name) __attribute__((section(name), used))

struct {
	int (*type)[2]; // BPF_MAP_TYPE_ARRAY
	int (*max_entries)[1];
	unsigned int *key;
	unsigned long long *value;
} state SEC(".maps");

static unsigned long long (*bpf_get_current_pid_tgid)(void) = (void *)14;
static long (*bpf_for_each_map_elem)(void *, void *, void *, unsigned long long) = (void *)164;

static __attribute__((noinline)) long visit(void *map, const unsigned int *key,
					 unsigned long long *value, void *ctx)
{
	*value = bpf_get_current_pid_tgid();
	return 0;
}

SEC("tracepoint/syscalls/sys_enter_nanosleep")
int observe(void *ctx)
{
	return bpf_for_each_map_elem(&state, visit, 0, 0);
}

char LICENSE[] SEC("license") = "GPL";
