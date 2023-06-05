# Support for containerized gadgets in Inspektor Gadget

TODO: intro

# Goals

TODO

# Categories of eBPF programs

Supported categories of eBPF programs:

| ebpf program type     | Support | Difficulty |
|-----------------------|---------|------------|
| socket                | 👷      |            |
| sk_reuseport/migrate  |         |            |
| sk_reuseport          |         |            |
| kprobe/               | ✅      |            |
| uprobe/               |         |            |
| kretprobe/            | ✅      |            |
| uretprobe/            |         |            |
| tc                    |         |            |
| classifier            |         |            |
| action                |         |            |
| tracepoint/           | 👷      |            |
| tp/                   |         |            |
| raw_tracepoint/       |         |            |
| raw_tp/               |         |            |
| raw_tracepoint.w/     |         |            |
| raw_tp.w/             |         |            |
| tp_btf/               |         |            |
| fentry/               |         |            |
| fmod_ret/             |         |            |
| fexit/                |         |            |
| fentry.s/             |         |            |
| fmod_ret.s/           |         |            |
| fexit.s/              |         |            |
| freplace/             |         |            |
| lsm/                  |         |            |
| lsm.s/                |         |            |
| iter/                 | 📅      |            |
| iter.s/               | 📅      |            |
| syscall               |         |            |
| xdp_devmap/           |         |            |
| xdp_cpumap/           |         |            |
| xdp                   |         |            |
| perf_event            |         |            |
| lwt_in                |         |            |
| lwt_out               |         |            |
| lwt_xmit              |         |            |
| lwt_seg6local         |         |            |
| cgroup_skb/ingress    |         |            |
| cgroup_skb/egress     |         |            |
| cgroup/skb            |         |            |
| cgroup/sock_create    |         |            |
| cgroup/sock_release   |         |            |
| cgroup/sock           |         |            |
| cgroup/post_bind4     |         |            |
| cgroup/post_bind6     |         |            |
| cgroup/dev            |         |            |
| sockops               |         |            |
| sk_skb/stream_parser  |         |            |
| sk_skb/stream_verdict |         |            |
| sk_skb                |         |            |
| sk_msg                |         |            |
| lirc_mode2            |         |            |
| flow_dissector        |         |            |
| cgroup/bind4          |         |            |
| cgroup/bind6          |         |            |
| cgroup/connect4       |         |            |
| cgroup/connect6       |         |            |
| cgroup/sendmsg4       |         |            |
| cgroup/sendmsg6       |         |            |
| cgroup/recvmsg4       |         |            |
| cgroup/recvmsg6       |         |            |
| cgroup/getpeername4   |         |            |
| cgroup/getpeername6   |         |            |
| cgroup/getsockname4   |         |            |
| cgroup/getsockname6   |         |            |
| cgroup/sysctl         |         |            |
| cgroup/getsockopt     |         |            |
| cgroup/setsockopt     |         |            |
| struct_ops+           |         |            |
| sk_lookup/            |         |            |
| seccomp               |         |            |
| kprobe.multi          |         |            |
| kretprobe.multi       |         |            |

Symbols:
- ✅: implemented
- 👷: work in progress
- 📅: desired feature, we should plan it

List of categories:
* https://github.com/cilium/ebpf/blob/v0.10.0/elf_reader.go#L1073
* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/libbpf.c

# Categories of gadgets

The category is automatically found with the following algorithm:
1. There is a eBPF map with the prefix "print_":
   1. The map type is RingBuf or PerfEventArray. Category: tracer.
   2. The map type is Hash or Array. Category: topper.
2. There is no eBPF map with the prefix "print_".
   1. The is a eBPF program of type "iter". Category: snapshotter.

## Tracer (stream of events)

IG notices eBPF maps of type RingBuf or PerfEventArray with the prefix "print_". Then, IG checks the BTF type of values
of the map. It uses this BTF information to parse the buffers from the ring buffers.

## Snapshotters

IG notices eBPF programs of type "iter/". Here we don't have maps with BTF information. IG runs the program and parses
the output from BPF_SEQ_PRINTF() calls in the following format:
```
[event]
fieldName1=fieldValue1\0
fieldName2=fieldValue2\0
```

Note that some fields such as `comm` can contain a new line character ("\n"), so we can't use only that as a separator.

Alternatively, the bpf module can contain a global variable with the same name as the iterator plus a suffix "_output".
So the BTF information can be attached to that variable.
```
const volatile event_t myiterator_output = {};

SEC("iter/task_file")
int myiterator(struct bpf_iter__task_file *ctx)
```

Problem: if that variable is not used by any program, the cilium/ebpf loader will complain.

## Toppers

TODO

# Reimplementing existing gadgets as containerized gadgets

For each existing gadget, we list the additional feature needed that are not yet supported for containerized containers
in Inspektor Gadget. For this exercise, we look at each gadget tracer.go and *.bpf.c file.

| Gadget                 | Feature needed                                                                  | Difficulty |
|------------------------|---------------------------------------------------------------------------------|------------|
| advise network-policy  |                                                                                 |            |
| advise seccomp-profile |                                                                                 |            |
| audit seccomp          |                                                                                 |            |
| profile block-io       |                                                                                 |            |
| profile cpu            |                                                                                 |            |
| profile tcprtt         |                                                                                 |            |
| snapshot process       |                                                                                 |            |
| snapshot socket        |                                                                                 |            |
| top block-io           |                                                                                 |            |
| top ebpf               |                                                                                 |            |
| top file               |                                                                                 |            |
| top tcp                |                                                                                 |            |
| trace bind             | field_filter, bitfield_column, enum_convert, ifindex                            |            |
| trace capabilities     |                                                                                 |            |
| trace dns              | socket_filter, socket_enricher, enum_convert, string_edit, ip_ver, latency_calc |            |
| trace exec             |                                                                                 |            |
| trace fsslower         |                                                                                 |            |
| trace mount            |                                                                                 |            |
| trace oomkill          |                                                                                 |            |
| trace open             |                                                                                 |            |
| trace signal           |                                                                                 |            |
| trace sni              | socket_filter, socket_enricher                                                  |            |
| trace tcp              |                                                                                 |            |
| trace tcpconnect       |                                                                                 |            |
| trace tcpdrop          |                                                                                 |            |
| trace tcpretrans       |                                                                                 |            |
| traceloop              |                                                                                 |            |

Features:
- socket_filter: attach ebpf program as a socket filter.
- socket_enricher: use the socket enricher from the ebpf code.
- enum_convert: converting an enum to a string. Examples: pktTypeNames, qTypeNames, rCodeNames, etc. Some could use BTF from the kernel, but not all.
- string_edit: string manipulation routines. Example: parseLabelSequence to replace dns strings to dotted names.
- ip_ver: converting an ip address to a string, depending on IPv4 or IPv6, and IPv4-mapped-IPv6.
- latency_calc: correlating two events to calculate the latency between them. Example: using Qr field in dns events.
- field_filter: filter events in ebpf before sending to userspace. Example: trace bind using filter_by_port.
- bitfield_column: convert bitfield from an event to a human readable string. Example: bind's optionsToString.
- ifindex: convert network interface index to string. Example: bind's BoundDevIf.

# Prometheus integration

TODO

## Counters

## Histograms

## Gauges

# Event enrichment

Implementation options:
- IG provides bpf extensions that gadgets can call to enrich events. This was the initial PoC.
- the ebpf program expose a field mount_ns_id. When IG notices that field, it will automatically add new fields such as
  pod name, namespace, etc.
- IG does not directly attach the ebpf program to the kprobe. Instead it attaches its own intermediary program to the
  kprobe, then the intermediary program does a tail call to the provided program. The intermediary program will send its
  own event on the ring buffer with the matching between the pid and the mount_ns_id. IG will then use that information
  to enrich the event. In this way, the gadget only needs to provide the pid of the process that triggered the event.
- Similarly to the socket enricher, IG maintains a global ebpf map linking processes to mount_ns_id. Entries are removed
  only after a timeout. Then, the gadget only needs to provide the pid of the process that triggered the event. IG will
  enrich the event in userspace.
- IG automatically replaces the bpf_perf_event_output() helper by its own bpf extension, similarly to the way we
  overwrite bpf_ktime_get_boot_ns() today. Problem: we can't pass non-scalar arguments to a bpf extension. 

# Filtering

Container based filtering (`--podname`) can be provided by a bpf extension implemented by IG.

Other filtering (`-F comm:nginx`) can be done by IG in userspace.

# User Experience

# Configuration File

IG uses a file config.json with mediaType `application/ebpf.oci.image.config.v1+json` as described by
https://github.com/solo-io/bumblebee/tree/main/spec#format

# Out of Scope

- TODO