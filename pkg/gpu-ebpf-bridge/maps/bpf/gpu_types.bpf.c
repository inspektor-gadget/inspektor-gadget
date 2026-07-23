// SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR Apache-2.0
/* Copyright (c) 2026 The Inspektor Gadget authors */

/*
 * gpu_types.bpf.c - establishes the gpu-ebpf-bridge maps in bpffs with BTF.
 *
 * This BPF object declares no programs and no entry points. Its sole
 * purpose is to carry the canonical struct definitions for the four
 * bridge maps into the kernel's BPF BTF, so that:
 *
 *   1. cilium/ebpf can create the maps with LIBBPF_PIN_BY_NAME and
 *      produce maps whose value_type_id refers to the BTF type we want
 *      consumers to CO-RE-read by name.
 *
 *   2. Tools like `bpftool map dump pinned <path>` automatically decode
 *      every field by name without needing an external schema.
 *
 *   3. Consumer eBPF gadgets that include <gadget/gpu_types.h> can use
 *      BPF_CORE_READ and bpf_core_field_exists() against the same
 *      struct layout.
 *
 * The bridge loads this object at startup, takes references to the four
 * maps (which arrive pinned at /sys/fs/bpf/<name> thanks to
 * LIBBPF_PIN_BY_NAME + cilium/ebpf MapOptions.PinPath), and then writes
 * to them directly via the Map.Update() API. There is no need to attach
 * or run any BPF program.
 */

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>

#define GPU_BRIDGE_WANT_ALL
#include <gadget/gpu_bridge_maps.h>

char __license[] SEC("license") = "Dual BSD/GPL";
