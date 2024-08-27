---
title: ebpf
sidebar_position: 10
---

The eBPF operator handles the [ebpf layer](../../spec/oci.md#the-ebpf-layer)
that contains an ELF file with the eBPF programs. This operator loads the
programs into the kernel and attaches them to the different hooks as specified
by the gadget developer.

## Instance Parameters

### `iface`

Network interface to attach networking programs to.

Fully qualified name: `operators.oci.ebpf.iface`

### `trace-pipe`

Print to the terminal the `/sys/kernel/debug/tracing/trace_pipe` file, i.e.
where the `bpf_printk()` function prints to. This is useful for debugging
gadgets.

Fully qualified name: `operators.oci.ebpf.trace-pipe`

### `map-fetch-interval`

Interval in which to iterate over maps.

Fully qualified name: `operators.oci.ebpf.map-fetcj-interval`

Default: `1000ms`

### `map-fetch-count`

Fully qualified name: `operators.oci.ebpf.map-fetch-count`

Number of map fetch cycles - use 0 for unlimited.

Default: `0`
