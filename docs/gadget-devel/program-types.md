---
title: 'eBPF Program Types'
sidebar_position: 310
description: 'Different eBPF programs supported by Inspektor Gadget'
---

Inspektor Gadget automatically loads and attaches the eBPF programs contained in a gadget. This
document describes the different types that are supported and specific details about them.
The section name specifies the type of the program and the target they should be attached to.

## Program Types

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

The section name must use the `fentry/<function_name>` or `fexit/<function_name>`. As in kprobes,
`<function_name>` is the kernel function that the program will be attached to.

### PerfEvents

The section name must be `perf_event/<name>`, where `<name>` is used to apply parameters to the
program using the `gadget.yaml` file.

Currently, we only support the following settings (`<name>` is `myPerfEvent` in this case):

```yaml
programs:
  myPerfEvent:
    perf:
      type: software
      config: count_sw_cpu_clock
      sampleType: sample_raw
    sampler:
      frequency: 49
```

All parameters are mandatory for now.

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

### SockOps

The section name must be `sockops`. `sock_ops` programs are invoked on TCP
socket lifecycle events (e.g. when a connection becomes established). Inspektor
Gadget attaches them to a cgroup v2. By default the cgroup v2 root is used, so
the program observes every socket on the host; this can be overridden per
program via the `programs.<name>.cgroup` configuration key.

`sock_ops` programs are typically used together with `sk_skb` and `sk_msg`
programs to observe TCP-stream application protocols: the `sock_ops` program adds
established sockets to a sockhash map, and the `sk_skb`/`sk_msg` programs then
process their stream data. The reusable [`<gadget/tcp_stream.h>`](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/tcp_stream.h)
header provides this plumbing. See [Parsing TCP-stream protocols](./tcp-stream-gadgets.md)
for a complete guide.

:::note

The `sock_ops` + `sk_skb` + `sk_msg` stream stack, and the `fexit/tcp_connect`
enrichment program used by `<gadget/tcp_stream.h>`, rely on socket cookies in
`sock_ops`, `BPF_MAP_TYPE_SOCKHASH`, `fexit` and kernel BTF. These are available
from Linux ≥ 5.7, within the project-wide minimum documented in
[Requirements](../reference/requirements.md). See
[Parsing TCP-stream protocols](./tcp-stream-gadgets.md#requirements-and-caveats)
for the full list.

:::

### SK_SKB (stream parser / verdict)

The section name must be `sk_skb/stream_parser` or `sk_skb/stream_verdict`.
`sk_skb` programs run on the reassembled TCP byte stream of sockets stored in a
sockmap/sockhash map, and are attached to that map (not to a kernel hook). The
target map is named by the `programs.<name>.attach_to` configuration key and
defaults to `gadget_sockhash`, the sockhash defined by
[`<gadget/tcp_stream.h>`](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/tcp_stream.h).

Because `sk_skb` programs operate on the TCP stream (rather than on individual
packets), they are convenient for parsing application protocols carried over
TCP, such as DNS-over-TCP or HTTP. Note that a `stream_verdict` program runs on
data *received* by the sockets in the map. See
[Parsing TCP-stream protocols](./tcp-stream-gadgets.md) for a complete guide.

### SK_MSG

The section name must be `sk_msg`. `sk_msg` programs are the send-path
counterpart of `sk_skb`: they run when data is *sent* on a socket that is in a
sockmap/sockhash map, and are attached to that map. As with `sk_skb`, the target
map is named by `programs.<name>.attach_to` and defaults to `gadget_sockhash`.
Combining an `sk_skb` `stream_verdict` (receive) with an `sk_msg` program (send)
lets a gadget observe both directions of a TCP-stream protocol. See
[Parsing TCP-stream protocols](./tcp-stream-gadgets.md) for a complete guide.

## Disabling Programs

You can disable a program by using `gadget_program_disabled` as the program
target. For example:

```c
SEC("kprobe/gadget_program_disabled")
int BPF_KPROBE(foo, args...)
{
	return 0;
}
```
