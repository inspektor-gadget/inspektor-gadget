// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

// legacy_encoding is a regression fixture for the permanent backward
// compatibility guarantee (see pkg/operators/ebpf/types.go): a new ig must keep
// loading pre-built gadget images that carry only the legacy "___"-style
// magic-global symbols and NO ig:* btf_decl_tags.
//
// It deliberately hand-writes the legacy encoding instead of using the
// GADGET_* macros, because those macros now emit ig:* decl tags. Writing the
// legacy symbols by hand freezes this object in the OLD encoding forever,
// independent of any future macro change, which is exactly what a pre-built old
// image looks like. Only basic types are used so the fixture compiles without
// vmlinux.h / kernel BTF.
//
// Rebuild with: make -C pkg/operators/ebpf/testdata legacy_encoding

// This fixture is fully self-contained: it defines the handful of libbpf
// macros/types it needs (SEC, __uint, BPF_MAP_TYPE_RINGBUF) rather than
// including any header. That keeps it independent of the BPF clang include path
// — in particular it avoids <linux/types.h>/<linux/bpf.h>, which transitively
// pull in <asm/types.h> (absent from the BPF target include path in CI) — and,
// fittingly, freezes it as a hand-written old-encoding object.
#define SEC(name) __attribute__((section(name), used))
#define __uint(name, val) int(*name)[val]

#define BPF_MAP_TYPE_RINGBUF 27

typedef unsigned long long __u64;

// --- Legacy GADGET_PARAM(myparam) encoding ---------------------------------
// The real tunable lives in .rodata as a const volatile variable; a throwaway
// gadget_param_<name> marker tells the ebpf operator it is a parameter.
const volatile int myparam = 0;
const void *gadget_param_myparam __attribute__((unused));

// --- Legacy gadget_var_ encoding -------------------------------------------
// A const volatile variable whose name carries the gadget_var_ prefix.
const volatile __u64 gadget_var_myvar = 0;

// --- Legacy GADGET_TRACER_MAP(events, ...) encoding ------------------------
// A ring buffer map plus a throwaway gadget_map_tracer_<name> marker.
struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 4096);
} events SEC(".maps");
const void *gadget_map_tracer_events __attribute__((unused));

char LICENSE[] SEC("license") = "GPL";
