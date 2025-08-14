---
title: 'Gadget eBPF API'
sidebar_position: 300
description: 'Gadget eBPF API Documentation'
---

The gadget helper API is a set of features exposed by Inspektor Gadget that is
accessible from eBPF code. These features simplify the creation of new gadgets
by providing convenient functions for common operations, making the developer's
life easier when implementing gadgets.

Gadgets define structures that contain the information provided to the users.
The fields of those structures are exposed in different ways according to the
format chosen by the user (json, columns, etc.). Inspektor Gadget provides some
special types that can be used to provide enrichment and other features as
described below.

## Ignoring fields

Fields starting with `__` are considered private and are ignored by Inspektor
Gadget.

## Container enrichment

To make use of container enrichment, gadgets must include
[gadget/mntns.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/mntns.h):

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
mntns_id = gadget_get_current_mntns_id();
```

eBPF programs of type socket filter cannot use `gadget_get_current_mntns_id()`, but instead
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

## Event filtering

One of the key functionalities of Inspektor Gadget is to efficiently filter
events in the kernel. Inspektor Gadget provides a set of helpers that should be
used by the Gadget authors. The following helpers (and in general any operation
that discards an event) should be executed as early as possible in the eBPF
program to minimize the performance overhead of processing events that will be
discarded.

The following helpers are available on the
[gadget/filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/filter.h)
file. Inspektor Gadget automatically exposes the `pid`, `tid`, `comm`, `uid`,
`gid` and container related parameters to the user when this file is included in
a Gadget.

### `gadget_should_discard_data`

```c
bool gadget_should_discard_data(gadget_mntns_id mntns_id, gadget_pid pid, gadget_tid tid,
		      gadget_comm comm[TASK_COMM_LEN], gadget_uid uid, gadget_uid gid)
```

This function receives the common fields of an event and returns `true` if it
should be discarded.

### `gadget_should_discard_data_current`

```c
bool gadget_should_discard_data_current()
```

This function returns `true` if an event should be discarded based on the
current process.

### Container filtering

To make use of container filtering, gadgets must include
[gadget/mntns_filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/mntns_filter.h):

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
[gadget/sockets-map.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/sockets-map.h).

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
struct gadget_socket_value {
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
struct gadget_socket_value *skb_val = gadget_socket_lookup(skb);
if (skb_val != NULL) {
	/* Access skb_val->mntns and other fields */
}
```

For eBPF programs of other kinds:

```C
struct gadget_socket_value *skb_val = gadget_socket_lookup(sk, netns);
if (skb_val != NULL) {
	/* Access skb_val->mntns and other fields */
}
```

### Optional Fields

Some of the fields provided by the socket enricher are optional and their size
is configurable, it means, the administrator configuring IG can disable them or
change their max size to reduce the resource consumption. In order to use these
fields, Gadgets MUST use `bpf_core_field_exists()` to check if a specific field
is enabled and `bpf_core_field_size()` to get their size.

```C
...
bool cwd_exists = bpf_core_field_exists(skb_val->cwd);
int cwd_len = bpf_core_field_size(skb_val->cwd);

if (cwd_exists) {
	bpf_probe_read_kernel_str(&event->cwd, cwd_len, skb_val->cwd);
}
...
```

## Enriched types

When a gadget emits an event with one of the following fields, it will be
automatically enriched, i.e. new field(s) containing more information will be
added to the event.

In some cases, these enrichments can be customized further by applying field
annotations. For further information about field annotations, see the
[metadata](metadata.md#field) documentation.

Some of the enriched fields (or their source fields) are hidden by default when
using the `columns` output mode. You can still access them by using either the
`json` output mode or the `--fields` flag as described in the [Selecting
specific fields](../reference/run.mdx#selecting-specific-fields) documentation.

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

By default this field is shown but you can use `columns.hidden` to the control visibility.

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

By default this field is shown but you can use `columns.hidden` to the control visibility.

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

It will produce the following output when using the `json` output mode:

```json
  "timestamp": "2024-07-25T21:34:07.136974948Z",
  "timestamp_raw": 1721943247136974800,
```

By default this field is hidden, but you can use `columns.hidden` to control visibility.

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

By default this field is hidden, but you can use `columns.hidden` to control visibility.

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

By default this field is hidden, but you can use `columns.hidden` to control visibility.

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

By default this field is hidden, but you can use `columns.hidden` to control visibility.

#### Annotations

- `formatters.syscall.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_file_mode`

File mode values will be converted to their string representation:

```c
struct event {
	gadget_file_mode mode_raw;
};
```

```json
  "mode": "-rw-r--r--",
  "mode_raw": 33188,
```

By default this field is hidden, but you can use `columns.hidden` to control visibility.

#### Annotations

- `formatters.file_mode.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_file_flags`

File flags values will be converted to their string representation:

```c
struct event {
	gadget_file_flags flags_raw;
};
```

```json
  "flags": "O_RDONLY|O_CREAT|O_TRUNC",
  "flags_raw": 577,
```

By default this field is hidden, but you can use `columns.hidden` to control visibility.

#### Annotations

- `formatters.file_flags.target`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_kernel_stack`

Symbolize the kernel stack from `gadget_get_kernel_stack(ctx)` (see [kernel-stack-traces](#kernel-stack-traces)).

#### Annotations

- `ebpf.formatter.kstack`: Name of the new field. If the annotation is not set and the source field name has a `_raw` suffix, the target name will be set to the source name without that suffix.

### `gadget_user_stack`

Symbolize the user stack from `gadget_get_user_stack(ctx, &event->ustack, collect_ustack)` (see [user-stack-traces](#user-stack-traces)).

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

### Automatic Annotations

In addition to the enrichment described above, using `gadget_` types will
automatically add annotations to those fields using the templates described in
[metadata](metadata.md#field)

This is also available for the following types:

- `gadget_pid`: Process PID
- `gadget_tid`: Process Thread ID
- `gadget_ppid`: Parent process PID
- `gadget_comm`: Process name
- `gadget_pcomm`: Parent process name

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

## Stack maps

### Kernel stack traces

To make use of kernel stack traces, gadgets must include
[gadget/kernel_stack_map.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/kernel_stack_map.h).

```C
#include <gadget/kernel_stack_map.h>
```

This will define the following struct:

```C
#define GADGET_KERNEL_MAX_STACK_DEPTH 127
#define GADGET_KERNEL_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, GADGET_KERNEL_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, GADGET_KERNEL_STACK_MAP_MAX_ENTRIES);
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

### User stack traces

To make use of user stack traces, gadgets must include
[gadget/user_stack_map.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/%IG_BRANCH%/include/gadget/user_stack_map.h).

```C
#include <gadget/user_stack_map.h>
```

This will define the following struct:

```C
#define GADGET_USER_MAX_STACK_DEPTH 127
#define GADGET_USER_STACK_MAP_MAX_ENTRIES 10000

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(key_size, sizeof(u32));
	__uint(value_size, GADGET_USER_MAX_STACK_DEPTH * sizeof(u64));
	__uint(max_entries, GADGET_USER_STACK_MAP_MAX_ENTRIES);
} ig_ustack SEC(".maps");
```

Then, add a field in the event structure with the type of `gadget_user_stack`,
designated for storing the stack id along with identifiers for the executable
so that the stack can be symbolised in userspace.
`gadget_get_user_stack(ctx, &event->ustack, collect_ustack)` could be used
to populate this field, this helper function will store the kernel stack into
`ig_ustack` and fill the field passed as parameter. When `collect_ustack` is
false, `ustack` is initialized to zero and ig will ignore the stack trace.

```C
struct event {
	struct gadget_user_stack ustack;
	/* other fields */
};

const volatile bool collect_ustack = false;
GADGET_PARAM(collect_ustack);

...
	struct event *event;
	event = gadget_reserve_buf(&events, sizeof(struct event));
	if (!event)
		return 0;

	gadget_get_user_stack(ctx, &event->ustack, collect_ustack);
```

## Metrics

Check [metrics](metrics.md#using-well-known-types-in-the-ebpf-code).

## Common information

Most gadgets provide common information like comm, pid, etc. Inspektor Gadget
provides some types and helpers to make it easier for gadgets to collect this
common information.

### Types

- `gadget_creds`: Contains the user id and group id.
- `gadget_parent`: Contains the name and pid of the parent process.
- `gadget_process`: Contains the name, pid, tid, user and parent of the process.

## Helpers

- `void gadget_process_populate(struct gadget_process *p)`: Fill `p` with
  the current process information
- `void gadget_process_populate_from_socket(const struct gadget_socket_value *skb_val, struct gadget_process *p)`:
  Fill `p` with the information on `skb_val` returned by `gadget_socket_lookup()`.

### Trailing Data

Tracers can add trailing data to the events they emit. This is useful for
gadgets that want to append optional data at the end of an event, like a
fragment of a network packet. Inspektor Gadget will create and store this data
on a field according to the `ebpf.rest.name` datasource annotation. The
`ebpf.rest.len` optional datasource annotation is used to set the name of the
field that contains the length of the trailing data. If the gadget doesn't
provide this annotation, the whole remaining data will be used as the trailing
data.
