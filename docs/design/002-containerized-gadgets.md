# Containerized Gadgets Support Inspektor Gadget

The gadgets we provide are heavily coupled to Inspektor Gadget as they are all developed on the same
repository and maintained by our team. Adding new gadgets implies that they have to be reviewed and
approved by us. This approach presents some disadvantages:
- Users need to install new versions of Inspektor Gadget to get new gadgets (or updates to them).
- Too specific gadgets can't be added to our code base.
- Users can't have private gadgets.

The [containerized gadgets idea](https://github.com/inspektor-gadget/inspektor-gadget/issues/1669)
aims to make Inspektor Gadget a framework to run eBPF programs (gadgets), like Docker does for
containers. This approach decouples the gadgets from Inspektor Gadget solving the issues mentioned
above.

Many ideas of this design document are based on [bumblebee](https://github.com/solo-io/bumblebee)
and [ebpf_exporter](https://github.com/cloudflare/ebpf_exporter) projects.

## User Experience

The UX we provide should be very close to the existing container runtimes like Docker. This document
considers the client-server setup for ig described in
https://github.com/inspektor-gadget/inspektor-gadget/issues/1681. It's being implemented at the time
of writing this document.

### `run`

The run command starts a gadget:

```bash
$ gadgetctl run mygadgetimage:latest
# print output to terminal
```

`mygadgetimage:latest` is a gadget OCI image.
This command should provide a flag to run on detached mode:

```bash
$ gadgetctl run mygadgetimage:latest --detach
a3397355fc4b2ba49cdc1ab2d36f728cbda65f0ef979854186f2ea780e8659e1
```

This command automatically pulls the image if it is not available in the local image cache.

### `list`

List print the running gadgets

```bash
$ gadgetctl list
...
```

### `attach`

Attach to a running gadget

```bash
$ gadgetctl attach mygadget
# gets terminal attached to the gadget
```

### `pull`

Pulls a gadget image

```bash
$ gadgetctl pull mygadgetimage:latest
```

### `build`

Builds and packages a gadget as an OCI image

```bash
$ gadgetctl build --prog foo.bpf.c --definition foo.yaml mygadgetimage:latest
```

Details of this command are still to be defined. Like other flags that are supported.

### `tag`

Tag an image

```bash
$ gadgetctl tag mygadgetimage:latest ghcr.io/foo/mygadgetimage:v1
```

### `login`

Login into a container registry

```bash
$ gadgetctl login -u admin -p 1234
```

### `image`

Different commands to handle images

- `image list`
- `image delete`
etc...

TODO: Should commands like `ig pull`, `ig build`, `ig push` be aliases of `ig image ...` ones?

## Gadget Packaging

Gadgets should be packed as [OCI](https://github.com/opencontainers/image-spec) images.
It is expected that the first manifest is an image index `application/vnd.oci.image.index.v1+json`.
All supported architectures has to be listed here
```bash
$ crane manifest ghcr.io/inspektor-gadget/tcp-connect:test | jq .
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:7138dd1d4599d3e2c010a08e2609d53bea0764809563ff4554b9f4c8116fafef",
      "size": 590,
      "platform": {
        "architecture": "amd64",
        "os": "linux"
      }
    },
    {
      "mediaType": "application/vnd.oci.image.manifest.v1+json",
      "digest": "sha256:9ecb3e8284068ce53d6c359b046ff20febf39f2d05ffa219e4665bd29fef1954",
      "size": 590,
      "platform": {
        "architecture": "arm64",
        "os": "linux"
      }
    }
  ]
}
```

The manifest referenced by the digest of a specific architecture has a config and a single layer. The content of the config is [the definition file](#def-file).
The currently single layer contains the compiled eBPF program. It supports configurable annotations for the author and description

Example:
```bash
$ crane manifest ghcr.io/inspektor-gadget/tcp-connect@sha256:9ecb3e8284068ce53d6c359b046ff20febf39f2d05ffa219e4665bd29fef1954 | jq .
{
  "schemaVersion": 2,
  "config": {
    "mediaType": "application/vnd.gadget.config.v1+yaml",
    "digest": "sha256:eb71861c0a5d5ca9a706fffa20fead54f64a1624dfeef5d334a8a3c2462c4c37",
    "size": 628,
    "annotations": {
      "org.opencontainers.image.title": "config.yaml"
    }
  },
  "layers": [
    {
      "mediaType": "application/vnd.gadget.ebpf.program.v1+binary",
      "digest": "sha256:a2e1f232e675b1a8d83f94fc646b40e885564f8346273c3257ac76003545880b",
      "size": 873256,
      "annotations": {
        "org.opencontainers.image.authors": "Burak Ok",
        "org.opencontainers.image.description": "A simple tcpconnect program",
        "org.opencontainers.image.title": "program.o"
      }
    }
  ]
}

```


TODO: How the user could specify these annotations when using the build command?

### Definition File <a name="def-file"></a>

The definition file contains the following information for a gadget:
- `documentation`: Long text describing how to use the gadget. This should describe the different
  parameters supported and can contain some practical examples about how to use it.
- `columns`: Information about the event that the gadget provides. Each element represents a columns
  attribute as defined in pkg/columns/columninfo.go.

This definition file is mandatory in the early implementation stage, but later on it'll be
optional.

## Gadget Implementation

A gadget is composed by eBPF programs and maps that are compiled into an eBPF ELF object. According
to the names of the maps and programs, and the types used, Inspektor Gadget is able to understand
how to parse, enrich and print information from the gadget.
Inspektor Gadget requires the ELF file to have sections named according to the convention defined in
libbpf and cilium/ebpf.

Currently the built-in gadgets have a strong categorization, however in this new containerized
gadgets approach that categorization is softer, each gadget defines how it behaves according to the
maps / types they use and it's possible that the same gadget implements different behaviors, like
tracer and topper, etc.

### Maps

#### `RingBuf` and `PerfEventArray` with `print_` Prefix (a.k.a tracers)

These maps indicate that the gadget produces a stream of events. Inspektor Gadget uses the BTF
information to format and print the events.

```c
// taken from gadgets/trace_open.bpf.c
struct event {
	__u64 timestamp;
	__u32 pid;
	__u32 uid;
	__u32 gid;
	mnt_ns_id_t mntns_id;
	int ret;
	int flags;
	__u16 mode;
	__u8 comm[TASK_COMM_LEN];
	__u8 fname[NAME_MAX];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__type(value, struct event);
} print_events SEC(".maps");
```

NOTE: In libbpf and cilium/ebpf, maps of type RingBuf and PerfEventArray normally have an explicit
definition with:

```c
__uint(value_size, sizeof(u32));
```

Or an implicit one (when value_size is not defined, the bpf loader understands that RingBuf and
PerfEventArray store a file descriptor, i.e. an integer of size 4).

However, for containerized gadgets, Inspektor Gadget changes the semantic of the value field in the
map definition to be able to carry the expected BTF type sent to the ring buffers. This idea
initially comes from Bumblebee.

As a consequence, BPF programs written in this way will not be loadable by generic bpf loaders but
only by Inspektor Gadget.

TODO: Revisit this appproach and check if there is a way to remove the limitation of being loaded by
other projects.

#### `HashMap` with `stats_` Prefix (a.k.a toppers)

These maps are used to implement toppers, i.e. gadgets that print a list of elements sorted by
specific parameters, like TCP connections by sent bytes.

Inspektor Gadget automatically reads and sorts those maps according to the configuration provided by the user:
- Interval: How often to print the map contents
- Sort by: Field within the event type to sort by

#### BPF Iterators (a.k.a snapshotters)

Programs of type `iter/` are automatically loaded and attached by Inspektor Gadget, then they are
triggered one time and its output is parsed according to the BTF information provided by it.

In order to have BTF information available, the programs have to define an unused variable with the
type they output in the iterator:

```c
const volatile event_t myiterator_output = {};

const struct myevent *gadget_iter_type __attribute__((unused));

SEC("iter/task_file")
int myiterator(struct bpf_iter__task_file *ctx)
```

According to the type of iterator, it's run in different ways:
- iter/task, iter/task_file: relative to the current pid namespace. Inspektor Gadget switches to the
  host pid namespace as appropriate to get all processes.
- iter/tcp, iter/udp: relative to the current network namespace. Inspektor Gadget iterates over all
  network namespaces of interest and triggers the program in each of them. (containers selected with
  the usual filter flags like --container)
- iter/bpf_map_elem: relative to a map. Unsupported.

#### `HashMap` with `hist_` Prefix (a.k.a profilers)

These maps are used to implement profilers: gadgets that output a histogram. The histogram collection
starts when the gadget is run, and it's printed when the gadgets stops.

TODO1: It's possible to also print the histogram periodically, however it's not explored yet.

TODO2: There is probably some overlap with histogram metrics support for Prometheus. It's very
likely that the same gadget can be used for both purposes.

#### Prometheus

TODO: We can heavily base this on https://github.com/cloudflare/ebpf_exporter.

##### Counters

##### Histograms

##### Gauges


### Inspektor Gadget API for Gadgets Developers

Inspektor Gadget provides some C header defining some types and functions to be used by gadgets.
Those types and functions are used to enable some of the features described below.

Please check the note in [Support Inspektor Gadget API
changes](#support-inspektor-gadget-api-changes) to get further details about handling changes in
this API.

#### Data Types and Helper Headers

Types provided in pkg/gadgets/common/types.h are used to format data in a specific way.

- `endpoint_t`: Represent an L3 or L4 endpoint. Inspektor Gadget automatically enriches it
  with the Kubernetes Pod and/or Service details corresponding to that IP address.
- pkg/gadgets/common/mntns_filter.h: used to filter and enrich data by mount namespace

### Types of eBPF programs

Inspektor Gadget automatically loads and attaches the eBPF programs. The following table describes
the current support and the future plans:

Symbols:
- ✅: implemented
- 👷: work in progress
- 📅: desired feature, we should plan it

| ebpf program type     | Support | Difficulty |
|-----------------------|---------|------------|
| socket_filter         |   👷    |            |
| sk_reuseport/migrate  |         |            |
| sk_reuseport          |         |            |
| kprobe/               |   ✅    |            |
| uprobe/               |         |            |
| kretprobe/            |   ✅    |            |
| uretprobe/            |         |            |
| tc                    |         |            |
| classifier            |         |            |
| action                |         |            |
| tracepoint/           |   ✅    |            |
| tp/                   |         |            |
| raw_tracepoint/       |         |            |
| raw_tp/               |         |            |
| raw_tracepoint.w/     |         |            |
| raw_tp.w/             |         |            |
| tp_btf/               |         |            |
| fentry/               |   📅    |            |
| fmod_ret/             |         |            |
| fexit/                |   📅    |            |
| fentry.s/             |         |            |
| fmod_ret.s/           |         |            |
| fexit.s/              |         |            |
| freplace/             |         |            |
| lsm/                  |         |            |
| lsm.s/                |         |            |
| iter/                 |   📅    |            |
| iter.s/               |   📅    |            |
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

List of categories:
* https://github.com/cilium/ebpf/blob/v0.10.0/elf_reader.go#L1073
* https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/tree/tools/lib/bpf/libbpf.c

## Gadgets Testing

Each gadget should take care of its own testing. Inspektor Gadget will provide some framework to
help gadget developers with this, like:
- Integration testing:
  https://github.com/inspektor-gadget/inspektor-gadget/blob/main/integration/helpers.go
- Unit tests: https://github.com/inspektor-gadget/inspektor-gadget/tree/main/internal/test

Inspektor Gadget will use some specific design gadgets for testing purposes to test that all the
APIs and functionality it provides to gadgets is working fine.

TODO: We need to double check this. IMO we shouldn't be testing external gadgets in Inspektor
Gadget, but there could be different opinions.

## Gadgets API

There are different ways for external applications to consume data provided by gadgets.

### Use Inspektor Gadget Daemon / Agent

NOTE: This is still under big discussion as the API for builtin gadgets is under development at the
time of writing this document.

In this case, Inspektor Gadget runs as an independent process, as an agent (`ig` case) or as a
DaemonSet (`ig-k8s` case), and the external applications communicates with IG by using its grpc or
other APIs. Those APIs should allow the external application to run a containerized gadget by
passing its image and parameters, and to consume the data the gadget generates.

The data the gadget generates don't have a specific format as it changes from gadget to gadget,
hence we'll need to use JSON or a similar protocol that allows us to encode unstructured data.

### Running Gadgets Directly

There are some cases where external applications want to run gadgets directly in their processes,
i.e. by using gadgets as a library. Currently, the different builtin gadgets provide golang packages
that can be consumed by external applications. Some examples are available in ../../examples. In the
containerized gadgets the same approach can't be used as these gadgets don't provide a golang
package.

In order to support this case with containerized gadgets, Inspektor Gadget should provide a golang
package that provides the primitives for applications to run and consume data generated by gadgets.

The following code snippet shows a raw idea of the API we should provide:

#### Running a Gadget from an OCI Image

```go
package main

import (
	"fmt"

	"ig.io/runner"
)

func main() {
	opts := runner.Opts{
		// Authentication options
		// Gadget parameters
		// etc.
	}
	gadget := runner.RunOCI("ghcr.io/foo/mygadget:v1", opts)
	defer gadget.Close()

	for !gadget.Done() {
		fmt.Print("event received: %+v\n", gadget.Next())
	}
}
```

#### Running a Gadget from is eBPF Object

```go
package main

import (
	"fmt"
	"io"

	"ig.io/runner"
)

func main() {
	myeBPFObject := io.ReadAll()
	// Or from a go:embed variable

	opts := runner.Opts{
		// Authentication options
		// Gadget parameters
		// etc.
	}

	gadget := runner.RunObject(myeBPFObject, opts)
	defer gadget.Close()

	for !gadget.Done() {
		fmt.Print("event received: %+v\n", gadget.Next())
	}
}
```

## Reimplementing existing gadgets as containerized gadgets

A long term vision of this support is to reimplement all gadgets as containerized gadgets, then
deprecated the built-in ones. This section presents the features Inspektor Gadget should support for
it and checks additional challenges by existing gadgets.

### Features

This section describes additional features needed by containerized containers in Inspektor Gadget.
Some of them are already supported and others are planned.

#### Filtering and enrichment by mount namespace id

Inspektor Gadget provides a set of helper functions in pkg/gadgets/common/mntns_filter.h for gadgets
that want to filter and enrich events based on the mount namespace inode id information. Inspektor
Gadget detects the presence of the `gadget_mntns_filter_map` map and populates it with the matching
containers to filter. Enriching is done by looking for the presence of a field with `mnt_ns_id_t`
type in the event.

#### Endpoint enrichment

Networking gadgets that want to enrich IP addresses with Pod and Services name can use the `gadget_l3endpoint_t` and `gadget_l4endpoint_t` types provided by Inspektor Gadget.

NOTE: It's under development at the time of writing this document in
https://github.com/inspektor-gadget/inspektor-gadget/pull/1825.

#### `socket_filter` programs

Attach ebpf programs of type `BPF_PROG_TYPE_SOCKET_FILTER`. These programs need to be attached in
each network namespace of interest. Currently it's handled by the
`pkg/gadgets/internal/networktracer` package. Somehow the same logic needs to be used for
containerized gadgets.

#### Socket enricher

Use the socket enricher from the ebpf code. This can be done in a very similar way to the
`gadget_mntns_filter_map`: Inspektor Gadget automatically keeps the sockets map updated and the
gadget can perform lookups in the map to get additional information about the socket.

Initially, this will be done in a static way, meaning that changing the way Inspektor Gadget does
the enriching would mean recompiling the containerised gadgets. Later we will need to implement
backward compatibility as discussed in [Support Inspektor Gadget API
changes](#support-inspektor-gadget-api-changes).

#### Custom parameters

Some gadgets define parameters in the eBPF code to change its behavior. They are declared with the
`const volatile` keywords. Those constants should be exposed to the user as parameters.

It could be implemented by using the pkg/params package.

#### Enum convert

Convert an enum to a string. Examples: pktTypeNames, qTypeNames, rCodeNames, etc. The BTF
information from the kernel and the eBPF program can be used. When using the one from the kernel, it
needs to be relocated to the current kernel.

#### String edit

string manipulation routines. Example: parseLabelSequence to replace dns strings to dotted names.

#### Bitfield

Convert bitfield from an event to a human readable string. Example: bind's [optionsToString](https://github.com/inspektor-gadget/inspektor-gadget/blob/b57f2bae31a46b40d8e0204b85099ae37f15d21d/pkg/gadgets/trace/bind/tracer/tracer.go#L154).

#### Iface index

Convert network interface index to string. Example: bind's [BoundDevIf](https://github.com/inspektor-gadget/inspektor-gadget/blob/b57f2bae31a46b40d8e0204b85099ae37f15d21d/pkg/gadgets/trace/bind/tracer/tracer.go#L236-L250).

#### Custom user space logic

There are some gadgets that have a lot of logic in user space. To support those gadgets, we'll need
to run custom code they provide. The design of this feature will be done later on once the features
described in this document are completed.

### Gadgets

This is the list of the existing gadgets and the considerations to port them to containerized
gadgets. The purpose of this section is to describe the needed features and not to provide a
solution for them.

#### advise network-policy

This one has a lot of custom logic in user space, it requires [custom user space
logic](#custom-user-space-logic)

#### advise seccomp-profile

TODO

#### audit seccomp

TODO

#### profile block-io

TODO

#### profile cpu

TODO

#### profile tcprtt

TODO

#### snapshot process

It supports a compatibility mode to get processes when iterators are not available ->
https://github.com/inspektor-gadget/inspektor-gadget/blob/e91a93bb2c0a7d05ed6ac2689b89ec7465923dcf/pkg/gadgets/snapshot/process/tracer/tracer.go#L216.
We'll lose that in the containerized version.

#### snapshot socket

Inspektor Gadget should automatically run the iter/ programs on the different network namespaces of
the containers.

#### top block-io

It has some logic to change the kprobe name based on the kernel support https://github.com/inspektor-gadget/inspektor-gadget/blob/9d8f024001c38d5677308b8d67289c5bcaf90d43/pkg/gadgets/top/block-io/tracer/tracer.go#L117-L130

#### top ebpf

- [Custom user space logic](#custom-user-space-logic).

#### top file

Nothing special is needed.

#### top tcp

- [Endpoint enrichment](#endpoint-enrichment)

#### trace bind

- [Enum convert](#enum-convert)
- [Bitfield](#bitfield)
- [Custom Parameters](#custom-parameters)
- [Iface index](#iface-index)

#### trace capabilities

- [Enum convert](#enum-convert)
- int to system call name conversion. Can we implement this as enum_convert given that syscalls are
  different per architecture?

#### trace dns

- [Socket filter](#socketfilter-programs)
- [Socket enricher](#socket-enricher)
- [Enum convert](#enum-convert)
- [Endpoint enrichment](#endpoint-enrichment)

#### trace exec

This gadget puts all arguments in an char array separated by null chars. `arg0\0arg1\0arg2\0...argN\0':
https://github.com/inspektor-gadget/inspektor-gadget/blob/b8cd8a7354952de416657279f3a49a89557bc0b1/pkg/gadgets/trace/exec/tracer/bpf/execsnoop.bpf.c#L90-L105
and then in user space those are divided into an slice of strings:
https://github.com/inspektor-gadget/inspektor-gadget/blob/b8cd8a7354952de416657279f3a49a89557bc0b1/pkg/gadgets/trace/exec/tracer/tracer.go#L158-L167
Perhaps we can generalize this?

#### trace fsslower

- [Enum convert](#enum-convert)
- The point where the probes of this gadget are attached to depends on a `--filesystem` flag. Those
  are defined as `k[ret]probe/dummy_...` and the real attach point is stored [in this
  map](https://github.com/inspektor-gadget/inspektor-gadget/blob/9d8f024001c38d5677308b8d67289c5bcaf90d43/pkg/gadgets/trace/fsslower/tracer/tracer.go#L68).

#### trace mount

- [Enum convert](#enum-convert)
- Similar to `bitfield_column`. It converts an integer to a list of strings in https://github.com/inspektor-gadget/inspektor-gadget/blob/8d034d79f422d5adaf971447860cc4e1299f7865/pkg/gadgets/trace/mount/tracer/utils.go#L52-L63. However this is not exactly the same as the mechanism used in "trace bind", in that case the result is a single string.

#### trace oomkill

Nothing

#### trace open

Already ported in gadgets/trace_open.bpf.c.

#### trace signal

- [Enum convert](#enum-convert)
- Attach programs based on parameters
  https://github.com/inspektor-gadget/inspektor-gadget/blob/efd6f979506ff446674d7b587cca0693bd1dd92c/pkg/gadgets/trace/signal/tracer/tracer.go#L136

#### trace sni

- [Socket filter](#socketfilter-programs)
- [Socket enricher](#socket-enricher)
- [Endpoint enrichment](#endpoint-enrichment)

#### trace tcp

- [Enum convert](#enum-convert)

#### trace tcpconnect

- Attach programs based on parameters. (Latency)

#### trace tcpdrop

- [Socket enricher](#socket-enricher)
- [Enum convert](#enum-convert)
- [Endpoint enrichment](#endpoint-enrichment)
- [Bitfield](#bitfield)

#### trace tcpretrans

- [Socket enricher](#socket-enricher)
- [Enum convert](#enum-convert)
- [Endpoint enrichment](#endpoint-enrichment)
- [Bitfield](#bitfield)


#### traceloop

TODO

## Future Work

This section explicitly describes the things that we don't want to support right now but that we'll
revisit later on:

### Support Inspektor Gadget API changes

Inspektor Gadget exposes a small [API](#inspektor-gadget-api) composed by some C headers to gadget
developers. Gadgets have to be compiled against it. In this iteration, we don't want to introduce
additional complexity by supporting changes to that API, i.e. gadgets need to be recompiled to take
changes in that API.

Later on we will consider solutions like bpf extensions or other forms of dynamic loading to solve
this problem.

### Supporting custom user space logic for gadgets

As exposed in [custom user space logic](#custom-user-space-logic), there are some gadgets that need
this to be implemented. However we consider that this is something very complicated and don't want
to tackle this right now.
