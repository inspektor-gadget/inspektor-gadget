---
title: 'eBPF Program Types'
sidebar_position: 310
description: 'Different eBPF programs supported by Inspektor Gadget'
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

The section name must use `iter/<iter_type>`. ig supports the following `<iter_type>`:
- `ksym`
- `task`
- `task_file`
- `tcp`
- `udp`

`tcp` and `udp` iterators are invoked in different network namespaces matching
the filter configuration when running the gadget.

You can find the list of iterator types supported by Linux with:
- `git grep -w ^DEFINE_BPF_ITER_FUNC` in the Linux sources (16 types as of Linux 6.9)
- `sudo bpftool btf dump id 1 format c |grep 'struct bpf_iter__'` in the current kernel

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

### Uprobes / Uretprobes

The section name must use the `<prog_type>/<file_path>:<symbol>` format.
`<prog_type>` must be either `uprobe` or `uretprobe`.
`<file_path>` is the absolute path of an executable or a library, that the uprobe will be attached to.
For common libraries, `<file_path>` can also be the library's name, such as `libc`.
`<symbol>` is a debugging symbol that can be found in the file mentioned above.

### User-Level Statically Defined Tracing (USDT)

The section name must use the `usdt/<file_path>:<providerName>:<probeName>` format.
`<file_path>` can be either an absolute path or a library name, same as the field in Uprobe.
`<providerName>` and `<probeName>` are two fields that can jointly identify a USDT trace point.

### Tracing with Linux Security Modules (LSM)

The section name must use the `lsm/<hook>` format.
The hook points could be found in [`<include/linux/lsm_hook_defs.h>`](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hook_defs.h).
