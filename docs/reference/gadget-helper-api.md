---
title: 'Gadget helper API'
weight: 10
description: 'Reference documentation for the gadget helper API'
---

The gadget helper API is a set of features exposed by Inspektor Gadget that is accessible from eBPF code.

## Container enrichment

To make use of container enrichment, gadgets must include
[gadget/mntns.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns.h):
```
#include <gadget/mntns.h>
```

Inspektor Gadget will automatically enrich events with container information
when the events include the mount namespace in this way:

```
struct event {
        gadget_mntns_id mntns_id;
        /* other fields */
}
```

An eBPF program can look up the mount namespace with the following:
```
u64 mntns_id;
mntns_id = gadget_get_mntns_id();
```

eBPF programs of type socket filter cannot use `gadget_get_mntns_id()`, but instead
use socket enrichment to find the mount namespace.

## Container filtering

To make use of container filtering, gadgets must include
[gadget/mntns_filter.h](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/include/gadget/mntns_filter.h):
```
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
```
#define GADGET_TYPE_NETWORKING
#include <gadget/sockets-map.h>
```

For eBPF programs of other kinds:
```
#define GADGET_TYPE_TRACING
#include <gadget/sockets-map.h>
```

This will define the following struct:
```
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

```
struct sockets_value *skb_val = gadget_socket_lookup(skb);
if (skb_val != NULL) {
        /* Access skb_val->mntns and other fields */
}
```

For eBPF programs of other kinds:

```
struct sockets_value *skb_val = gadget_socket_lookup(sk, netns);
if (skb_val != NULL) {
        /* Access skb_val->mntns and other fields */
}
```

## Enriched types

When a gadget emits an event with one of the following fields, it will be
automatically enriched.

```
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
