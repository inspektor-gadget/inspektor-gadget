---
title: 'Gadget eBPF API'
sidebar_position: 300
description: 'Gadget eBPF API Documentation'
---

The gadget helper API is a set of features exposed by Inspektor Gadget that is
accessible from eBPF code. These features simplify the creation of new gadgets
by providing convenient functions for common operations, making the developer's
life easier when implementing gadgets.

## Container enrichment

To make use of container enrichment, gadgets must include
[gadget/mntns.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns.h):

```C
#include <gadget/mntns.h>
```

Inspektor Gadget will automatically enrich events with container information
when the events include the mount namespace inode ID (see
https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) in this way:

:::warning

You can only have one field of this type in a `struct`.

:::

```C
struct event {
	gadget_mntns_id mntns_id;
	/* other fields */
}
```

An eBPF program can look up the mount namespace inode ID with the following:

```C
u64 mntns_id;
mntns_id = gadget_get_mntns_id();
```

eBPF programs of type socket filter cannot use `gadget_get_mntns_id()`, but instead
use [socket enrichment](#socket-enrichment) to find the mount namespace.

The following fields can be added from the mount or net namespace inode ID. The
exact fields that are added depend on the environment (Kubernetes vs local host)
and the container runtime (docker, cri-o, containerd, etc.).

| Field                        | Description                                      |
|------------------------------|--------------------------------------------------|
| k8s.node                     | Name of the k8s node                             |
| k8s.namespace                | Name of the k8s namespace                        |
| k8s.podName                  | Name of the k8s pod                              |
| k8s.containerName            | Name of the k8s container name                   |
| k8s.hostnetwork              | true, if the container is using the host network |
| runtime.containerName        | Name of the container on the container runtime   |
| runtime.runtimeName          | Name of the used container runtime               |
| runtime.containerId          | ID of the container                              |
| runtime.containerImageName   | Name of the container image, e.g. `nginx:latest` |
| runtime.containerImageDigest | Digest (hash value) of the container image       |

## Container filtering

To make use of container filtering, gadgets must include
[gadget/mntns_filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns_filter.h):

```C
#include <gadget/mntns_filter.h>
```

eBPF programs should stop processing an event when it does not originate from a
container the user is interested in.

```C
if (gadget_should_discard_mntns_id(mntns_id))
	return 0;
```

## Socket enrichment

To make use of socket enrichment, gadgets must include
[gadget/sockets-map.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/sockets-map.h).

For eBPF programs of type socket filter:

```C
#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>
```

For eBPF programs of other kinds:

```C
#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>
```

This will define the following struct:

```C
#define TASK_COMM_LEN 16
struct sockets_value {
	__u64 mntns;
	__u64 pid_tgid;
	__u64 uid_gid;
	char task[TASK_COMM_LEN];
	/* other private fields */
};
```

Then, an eBPF program can find additional details about a socket with
`gadget_socket_lookup()`. There are two different definitions of this function
depending on the eBPF program type. The developer must define either
`GADGET_TYPE_NETWORKING` or `GADGET_TYPE_TRACING` to define the right one. It
can return NULL if the socket is not found.

For eBPF programs of type socket filter:

```C
struct sockets_value *skb_val = gadget_socket_lookup(skb);
if (skb_val != NULL) {
	/* Access skb_val->mntns and other fields */
}
```

For eBPF programs of other kinds:

```C
struct sockets_value *skb_val = gadget_socket_lookup(sk, netns);
if (skb_val != NULL) {
	/* Access skb_val->mntns and other fields */
}
```

## Enriched types

When a gadget emits an event with one of the following fields, it will be
automatically enriched, i.e. new field(s) containing more information will be
added to the event.

In some cases, these enrichments can be customized further by applying field
annotations. For further information about field annotations, see the
[metadata](metadata.md#field) documentation.

### `gadget_mntns_id` and `gadget_netns_id`

See [Container enrichment](#container-enrichment)

### `struct gadget_l3endpoint_t`

Represents a layer 3 endpoint (IP address). It's defined as:

```C
struct gadget_l3endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u8 version; // 4 or 6
};
```

The IP field will be translated to its string representation:

```json
  "src": {
    "addr": "172.17.0.2",
    "version": 4
  },
```

### `struct gadget_l4endpoint_t`

Represents a layer 4 endpoint (IP address + port) for UDP and TCP. It's defined as:

```C
struct gadget_l4endpoint_t {
	union gadget_ip_addr_t addr_raw;
	__u16 port; // L4 port in host byte order
	__u16 proto; // IP protocol number
	__u8 version; // 4 or 6
};
```

It'll produce an output like:

```json
  "src": {
    "addr": "172.17.0.2",
    "port": 46076,
    "proto": 6,
    "version": 4
  },
```

or `172.17.0.2:46076` depending on the output mode used.


### `gadget_timestamp`

Add human-readable timestamp from `bpf_ktime_get_boot_ns()` for a timestamp usually gotten with `bpf_ktime_get_boot_ns()`.

```c
struct event {
	gadget_timestamp timestamp_raw;
};

...
event->timestamp_raw = bpf_ktime_get_boot_ns();
...
```

```json
  "timestamp": "2024-07-25T21:34:07.136974948Z",
  "timestamp_raw": 1721943247136974800,
```

#### Annotations

- `formatters.timestamp.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.
- `formatters.timestamp.format`: Format used for the timestamp. By default, it uses `2006-01-02T15:04:05.000000000Z07:00`, see https://pkg.go.dev/time#pkg-constants for more information.

### `gadget_signal`

Numeric signal values will be converted to the Unix [signals](https://man7.org/linux/man-pages/man7/signal.7.html).names like `SIGKILL`, `SIGINT`.

```c
struct event {
	gadget_signal sig_raw;
};
```

```json
  "sig": "SIGURG",
  "sig_raw": 23,
```

#### Annotations

- `formatters.signal.target`: Name of the new field. If the annotation is not set and the source field name has a _raw suffix, the target name will be set to the source name without that suffix.

### `gadget_errno`

Unix [errno](https://man7.org/linux/man-pages/man3/errno.3.html) will be converted to its name.

```c
struct event {
	gadget_errno error_raw;
};
```

```json
  "error": "ENOENT",
  "error_raw": 2,
```

#### Annotations

- `formatters.errno.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_syscall`

Unix [syscalls](https://man7.org/linux/man-pages/man2/syscalls.2.html) will be converted to its name:

```c
struct event {
	gadget_syscall syscall_raw;
};
```

```json
  "syscall": "SYS_SOCKET",
  "syscall_raw": 41,
```

#### Annotations

- `formatters.syscall.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_kernel_stack`

Symbolize the kernel stack from `gadget_get_kernel_stack(ctx)` (see [kernel-stack-maps](#kernel-stack-maps)).

#### Annotations

- `ebpf.formatter.kstack`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_uid` and `gadget_gid`

The `uid` and `gid` saved to these types will be resolved to the corresponding username and groupname on the host system:

```c
struct event {
	gadget_uid user_raw;
};
```

```json
  "user": "root",
  "user_raw": 0,
```

#### Annotations

- `uidgidresolver.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### Enumerations

Inspektor Gadget supports enums already defined on the kernel or enums defined
by the user. The event struct must contain a field with the enumeration.

```c
enum my_enum {
	FOO = 1,
	BAR = 2,
};

struct event {
	...
	enum my_enum myfield_raw;
	...
}

...
	event->myfield_raw = BAR;
...
```

A new field with the name of the enum will be added to the event:

```json
  "myfield": "BAR",
  "myfield_raw": 2,
```

#### Annotations

- `ebpf.formatter.enum`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### Bitfields

The support for bitfields is very similar to the enums. In this case the enum
type needs to have the `_set` suffix:

```c
enum flags_set {
	FOO = 0x01,
	BAR = 0x02,
};

struct event {
	...
	enum flags_set flags_raw;
	...
}

...
	event->flags_raw = FOO | BAR;
...
```

A new field containing the flags set will be added to the event:

```json
  "flags": "FOO|BAR",
  "flags_raw": 3,
```

#### Annotations

- `ebpf.formatter.enum`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.
- `ebpf.formatter.bitfield.separator`: Separator used. Defaults to `|`.

## Buffer API

There are two kind of eBPF maps used to send events to userspace: (a) perf ring
buffer or (b) eBPF ring buffer. The later is more efficient and flexible,
however it's only available from kernel 5.8. Check [this blog
post](https://nakryiko.com/posts/bpf-ringbuf/) to get more details about the
differences. `<gadget/buffer.h>` provides an abstraction to automatically use
the right buffer according to the kernel features.

First, you need to declare the buffer with the following macro:

```C
GADGET_TRACER_MAP(events, 1024 * 256);
```

Then, you can interact with the buffer using these functions:

1. `void *gadget_reserve_buf(void *map, __u64 size)`: Reserves memory in the corresponding buffer.
1. `long gadget_submit_buf(void *ctx, void *map, void *buf, __u64 size)`: Writes the previously reserved memory in the corresponding buffer.
1. `void gadget_discard_buf(void *buf)`: Discards the previously reserved buffer. This is needed to avoid wasting memory.
1. `long gadget_output_buf(void *ctx, void *map, void *buf, __u64 size)`: Reserves and writes the buffer in the corresponding map. This is equivalent to calling `gadget_reserve_buf()` and `gadget_submit_buf()`.

The following snippet demonstrates how to use the code available in `<gadget/buffer.h>`, it is taken from `trace_open`:

```C
#include <gadget/buffer.h>

/* ... */

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exit, events, event);

/* ... */

static __always_inline int trace_exit(struct syscall_trace_exit *ctx)
{
	struct event *event;

	/* ... */

	event = gadget_reserve_buf(&events, sizeof(*event));
	if (!event)
		goto cleanup;

	/* fill the event here */

	/* ... */
	gadget_submit_buf(ctx, &events, event, sizeof(*event));

	/* ... */
}
```

If you know you will not make use of `gadget_reserve_buf()/gadget_submit_buf()` and only rely on `gadget_output_buf()`, you can define the `GADGET_NO_BUF_RESERVE` macro before including `<gadget/buffer.h>`.
This will not declare the map associated with `gadget_reserve_buf()` as well as the other functions.
Here is an example, taken from `trace_exec`, of using `gadget_output_buf()`:

```C
#define GADGET_NO_BUF_RESERVE
#include <gadget/buffer.h>

/* ... */

GADGET_TRACER_MAP(events, 1024 * 256);

GADGET_TRACER(exec, events, event);

/* ... */

SEC("tracepoint/syscalls/sys_exit_execve")
int ig_execve_x(struct syscall_trace_exit *ctx)
{
	/* ... */
	struct event *event;

	/* ... */

	event = bpf_map_lookup_elem(&execs, &pid);
	if (!event)
		return 0;

	/* ... */

	if (len <= sizeof(*event))
		gadget_output_buf(ctx, &events, event, len);

	/* ... */
}
```

## Kernel stack maps

To make use of kernel stack maps, gadgets must include
[gadget/kernel_stack_map.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/43d7b29f43d6ced34004ed20a7508c25cf6a5fb9/include/gadget/kernel_stack_map.h).

```C
#include <gadget/kernel_stack_map.h>
```

This will define the following struct:

```C
#define PERF_MAX_STACK_DEPTH 127
#define MAX_ENTRIES	10000
struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, PERF_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, MAX_ENTRIES);
} ig_kstack SEC(".maps");
```

Then, add a field in the event structure with the type of `gadget_kernel_stack`,
designated for storing the stack id. `gadget_get_kernel_stack(ctx)` could be used
to populate this field, this helper function will store the kernel stack into
`ig_kstack` and returns the stack id (positive or null) as the key. It will return
a negative value on failure.

```C
struct event {
	gadget_kernel_stack kstack;
	/* other fields */
};

struct event *event;
long kernel_stack_id;

event = gadget_reserve_buf(&events, sizeof(*event));
kernel_stack_id = gadget_get_kernel_stack(ctx);
if (kernel_stack_id >= 0) {
	event->kstack = kernel_stack_id;
} else {
	// gadget_get_kernel_stack() failed
}
```
