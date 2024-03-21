---
title: 'Gadget helper API'
weight: 10
description: 'Reference documentation for the gadget helper API'
---

The gadget helper API is a set of features exposed by Inspektor Gadget that is accessible from eBPF code.

## Container enrichment

To make use of container enrichment, gadgets must include
[gadget/mntns.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns.h):

```C
#include <gadget/mntns.h>
```

Inspektor Gadget will automatically enrich events with container information
when the events include the mount namespace in this way:

```C
struct event {
        gadget_mntns_id mntns_id;
        /* other fields */
}
```

An eBPF program can look up the mount namespace with the following:

```C
u64 mntns_id;
mntns_id = gadget_get_mntns_id();
```

eBPF programs of type socket filter cannot use `gadget_get_mntns_id()`, but instead
use socket enrichment to find the mount namespace.

## Container filtering

To make use of container filtering, gadgets must include
[gadget/mntns_filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns_filter.h):

```C
#include <gadget/mntns_filter.h>
```

eBPF programs should stop processing an event when it does not originate from a
container the user is interested in.

```
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

Then, an eBPF can find additional details about a socket with
`gadget_socket_lookup()`. There are two different definitions of this function
depending on the eBPF program type. The developer must define either
`GADGET_TYPE_NETWORKING` or `GADGET_TYPE_TRACING` to define the right one.
It can return NULL if the socket is not found.

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
automatically enriched.

```C
struct event {
        struct gadget_l3endpoint_t  field1;
        struct gadget_l4endpoint_t  field2;
        gadget_mntns_id             field3;
        gadget_timestamp            field4;
}
```

* `struct gadget_l3endpoint_t` and `struct gadget_l4endpoint_t`: enrich with the Kubernetes endpoint. TODO: add details.
* `typedef __u64 gadget_mntns_id`: container enrichment (see #container-enrichment)
* `typedef __u64 gadget_timestamp`: add human-readable timestamp from `bpf_ktime_get_boot_ns()`.

## Buffer API

There are two kind of eBPF maps used to send events to userspace: (a) perf ring buffer or (b) eBPF
ring buffer. The later is more efficient and flexible, however it's only available from kernel 5.8.
Check https://nakryiko.com/posts/bpf-ringbuf/ to get more details about the differences.
`<gadget/buffer.h>` provides an abstraction to automatically use the right buffer according to the
kernel features.

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
