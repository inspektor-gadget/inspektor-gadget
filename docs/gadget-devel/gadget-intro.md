---
title: Gadget Introduction
sidebar_position: 100
description: Introduction to Gadgets
---

Gadgets are the central component in the Inspektor Gadget framework. A Gadget is
an [OCI image](https://opencontainers.org/) that includes one or more eBPF
programs, metadata YAML file and, optionally, WASM modules for post processing,
etc. As OCI images, they use the same tooling as containers and share the same
attributes; shareable, modular, deployable, etc.

## Data Sources

Data sources are the way a Gadget provides information. A single Gadget can
provide multiple data sources.


:::warning

We are still discussing possible naming changes to this.

:::

### Data Sources Types

There are several types of data sources according to the way the information is
collected and presented.

### Tracers

Tracers are data sources that provide a stream of events as they happen on the
system: a file is opened, a DNS request is performed, etc. These data sources use
a [perf ring
buffer](https://docs.kernel.org/next/userspace-api/perf_ring_buffer.html) or
[BPF ring buffer](https://docs.kernel.org/6.6/bpf/ringbuf.html) to transfer the
events from the Gadget to Inspektor Gadget.

Gadgets providing this kind of data source need to define an event `struct` with
the fields they provide:

```c
struct event {
	// all fields here
};
```

Tracers are registed by using the `.tracers` section:

```c
// Force the compiler to emit BTF information for the event structure
GADGET_GEN_TYPE_BTF(struct structname);

struct {
	__type(type, struct structname);
	__type(map, mapname);
} name SEC(".tracers");
```

`GADGET_GEN_TYPE_BTF` macro is needed to ensure that the BTF information for
the event structure is generated.

- name: Name of the tracer data source
- mapname: Name of the perf ring buffer of BPF ring buffer used by the program
- structname: Name of the structure defining the gadget's event

Examples of Gadgets that use this kind of data sources are
[trace_open](https://github.com/inspektor-gadget/inspektor-gadget/tree/%IG_BRANCH%/gadgets/trace_open),
[trace_exec](https://github.com/inspektor-gadget/inspektor-gadget/tree/%IG_BRANCH%/gadgets/trace_exec),
etc.

### Map Iterators

Map Iterators are used to report statistics like number of files being opened,
bytes going through a network connection, etc. The information is saved by the
Gadget on hash maps where it's then read by Inspektor Gadget.

Gadgets need to define the fields for the key and value and a hash map used to store the information:

```c
struct key {
	// fields in key
};

struct value {
	// fields in value
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct key);
	__type(value, struct value);
} stats SEC(".maps");
```

and then register the data source by using the `.mapiters` section:

```c
struct {
	__type(map, mapname);
} name SEC(".mapiters");
```

- name: Name of the data source
- mapname: Name of the hash map used to store the data

Currently, Map Iterator data sources only support iterating over maps of type
`BPF_MAP_TYPE_HASH` with keys and values of type `struct`.

[top_file](https://github.com/inspektor-gadget/inspektor-gadget/tree/%IG_BRANCH%/gadgets/top_file)
is an example of a gadget using this data source.

### Snapshotters

TODO
