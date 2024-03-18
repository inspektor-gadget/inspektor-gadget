---
title: 'eBPF Program Types'
weight: 50
description: 'Reference documentation for different eBPF programs supported by Inspektor Gadget'
---

Inspektor Gadget automatically loads and attaches the eBPF programs contained in a gadget. This
document describes the different types that are supported and specific details about them.
The section name specifies the type of the program and the target they should be attached to.

### Kprobes / Kretprobes

The section name must use the `kprobe/<function_name>` or `kretprobe/<function_name>` formats.
`<function_name>` is the kernel function that the kprobe will be attached to.

### Tracepoints

The section name must use the `tracepoint/<tracepoint_name>`. `<tracepoint_name>` is one of the
available tracepoints on `/sys/kernel/debug/tracing/events`.

### Socket Filter

The section name must start with `socket`. Socket programs are attached to all network namespaces
matching the filter configuration when running the gadget.

### Tracing

Currently we support some iterators and fentry/fexit programs.

#### Iterators

The section name must use `iter/<iter_type>`. `<iter_type>` is one of `task`, `tcp` or `udp`. `tcp`
and `udp` iterators are invoked in different network namespaces matching the filter configuration
when running the gadget.

#### Fentry / Fexit

The section name must use the `fentry/<function_name` or `fexit/<function_name>`. As in kprobes,
`<function_name>` is the kernel function that the kprobe will be attached to.

### Raw Tracepoints

TODO!

### SchedCLS

The section name must use the `classifier/<ingress|egress>/<program_name>` format. SchedCLS programs
are attached to the peer of the networking interface of the containers on the host according to the
filtering configuration.

Inspektor Gadget supports running multiple gadgets that use SchedCLS programs at the same time.
Programs must return `TC_ACT_UNSPEC` in order to allow the packet to be processed by other gadgets.
The order of execution of the programs is not deterministic, this is something we could visit later
on.

### Uprobes / Uretprobes (experimental)

The section name must use the `<prog_type>/<file_path>:<symbol>` format.
`<prog_type>` must be either `uprobe` or `uretprobe`.
`<file_path>` is the absolute path of an executable or a library, that the uprobe will be attached to.
For common libraries, `<file_path>` can also be the library's name, such as `libc`.
`<symbol>` is a debugging symbol that can be found in the file mentioned above.
