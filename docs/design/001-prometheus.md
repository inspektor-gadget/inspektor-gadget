# Prometheus support in Inspektor Gadget

Inspektor Gadget has a lot of tools that hook into the kernel to capture different events like file
opened, process created, DNS requests, etc. Currently it's mostly designed as a troubleshooting
tool: it prints those events as they happen to the terminal. However, it's an easy win to provide
metrics through Prometheus. The whole logic to capture the data is already in place, we only need to
aggregate and expose this in a Prometheus format.

This document contains a design proposal for supporting Prometheus metrics in Inspektor Gadget.
Upstream issue:
[https://github.com/inspektor-gadget/inspektor-gadget/issues/1513](https://github.com/inspektor-gadget/inspektor-gadget/issues/1513)

# Goals

This document is written with the following goals in mind in descending order of priority.

- Bring this support soon to market
- Metrics to expose should be configurable
- The solution should be performant

# Design Decisions

## Metrics to expose

In order to be as flexible as possible, the user should be able to configure the metrics they want to expose
for each gadget. Most gadgets emit events from eBPF including several fields of data and send them to the
userspace part of IG for processing. In a generic solution, most of these fields should be selectable for metric collection, aggregation and filtering. However, due to handling all events in userspace, this could negatively
impact performance. In order to improve that, we also propose a way to handle collection of the most commonly
used metrics directly in eBPF.

## Labels Granularity

High cardinality (a lot of distinct label combinations) can be problematic as it increases the memory
usage of both the collector (IG) and the consumer (Prometheus). As stated above, users should still be able
to configure the granularity they want to have and so should consider the cardinality themselves.

## Filtering

Inspektor Gadget already provides a mechanism to filter out events we're not interested in. This
mechanism should be reused by the Prometheus integration to avoid handling metrics for objects the
user is not interested in.

# User Experience

The metric collection and export to Prometheus should be supported in both cases, a) when running in Kubernetes (ig-k8s), and b) when running on Linux hosts (ig).
This is possible by implementing this using a new Prometheus gadget/operator as it makes the code automatically shareable between ig, ig-k8s and external applications. This gadget/operator provides
start / stop operations to enable / disable collection of metrics.

```bash
$ kubectl gadget prometheus start --config <path>
$ kubectl gadget prometheus stop
```

TODO: need to think about not having a start operation on this one

```bash
$ ig prometheus --config <path>
```

It should also be possible to configure the metrics using a CR - supporting a [static
configuration](https://github.com/inspektor-gadget/inspektor-gadget/issues/1401) could be
implemented in the future as well.

## Configuration File

Given that we want this to be flexible, allowing the user to control which metrics to capture
and how to aggregate them, we will use configuration files to define those aspects. This takes inspiration from
[https://github.com/cloudflare/ebpf_exporter](https://github.com/cloudflare/ebpf_exporter).

### Filtering (aka Selectors)

The user should be able to provide a set of filters indicating the events that should be taken into
consideration when collecting the metrics. The mechanism should provide the following features:

- Equal operator
  - "columnName:value"
- Different operator (!)
  - "columnName:!value"
- Greater than, less than operators (<, >, <=, >=)
  - "columnName:>value"
- Match regex (~)
  - "columnName:~regex"

In the future, we could consider introducing more advanced operators like:

- Set based
  - In
  - NotIn

It's similar to the existing [Labels and
Selectors](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/) mechanism, but
we still need to understand if we can reuse that or if we need a completely new implementation.

Some examples of possible filters are:

# Only metrics for default namespace

```yaml
# Only metrics for default namespace
selector:
  - k8s.namespace: default

# Count only events with retval != 0
selector:
  - "retval:!0"
```

The configuration file defines the different metrics to collect.

### Counters

This is probably the most intuitive metric: "A _counter_ is a cumulative metric that represents a
single [monotonically increasing counter](https://en.wikipedia.org/wiki/Monotonic_function) whose
value can only increase or be reset to zero on restart. For example, you can use a counter to
represent the number of requests served, tasks completed, or errors." from
[https://prometheus.io/docs/concepts/metric_types/#counter](https://prometheus.io/docs/concepts/metric_types/#counter).

The following are examples of counters we can support with the existing gadgets. The first one
counts the number of executed processes.

```yaml
metrics:
  # executed processes by namespace, pod and container.
  - name: executed_processes
    type: counter
    category: trace
    gadget: exec
    labels:
      - k8s.namespace
      - k8s.pod
      - k8s.container
```

The category and gadget fields define which gadget to use. The labels indicate how metrics are
aggregated, i.e., the cardinality of the exposed metric. In this case, we'll have a counter for each
namespace, pod and container combination.

Another example that will report the number of executed processes, aggregated by comm and namespace:

# executed processes by comm and namespace

```yaml
- name: executed_processes_by_comm
  type: counter
  category: trace
  gadget: exec
  labels:
    - k8s.namespace
    - comm
```

It is possible to count events based on matching criteria. For instance, the following counter
will only consider events in the default namespace.

```yaml
# executed processes by pod and container in the default namespace
- name: executed_processes
  type: counter
  category: trace
  gadget: exec
  labels:
    - k8s.pod
    - k8s.container
  selector:
    - "k8s.namespace:default"
```

Or only count events for a given command:

```yaml
# cat executions by namespace, pod and container
- name: executed_cats # ohno!
  type: counter
  category: trace
  gadget: exec
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container
  selector:
    - "comm:cat"
```

And finally, we can provide counters for failed operations:

```yaml
# failed execs by namespace, pod and container
- name: failed_execs
  type: counter
  category: trace
  gadget: exec
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container
  selector:
    - "retval:!0"
```

Filtering can also be used for gadgets that provide events describing two different situations, for
instance the trace dns gadget emits events for requests and answers. Then, we can expose a counter
only for requests based on the value of the "qr" field.

```yaml
# DNS requests aggregated by namespace and pod
- name: dns_requests
  type: counter
  category: trace
  gadget: dns
  labels:
    - namespace
    - pod
  selector:
    # Only count query events
    - "qr:Q"
```

Another example is:

```yaml
  # bpf seccomp violations
- name: seccomp_violations
  type: counter
  category: audit
  gadget: seccomp
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container
    - syscall
  selector:
    - "syscall:bpf"
```

By default, a counter is increased by one each time there is an event, however it's possible to
increase a counter using a field on the event:

```yaml
# Read bytes on ext4 filesystem
- name: read_bytes_ext4
  type: counter
  category: trace
  gadget: fsslower
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container
  field: bytes
  selector:
    - "filesystem:ext4"
    - "op:R"
```

## Gauges

"A _gauge_ is a metric that represents a single numerical value that can arbitrarily go up and down"
from
[https://prometheus.io/docs/concepts/metric_types/#gauge](https://prometheus.io/docs/concepts/metric_types/#gauge).

It seems that the only category of gadgets that can provide data to be interpreted as a gauge is the
snapshotters.

```yaml
# Number of processes by namespace / pod / container
- name: number_of_processes
  type: gauge
  category: snapshot
  gadget: process
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container

# Number of sockets in CLOSE_WAIT state
- name: number_of_sockets_close_wait
  type: gauge
  category: snapshot
  gadget: socket
  labels:
    - k8s.namespace
    - k8s.pod
    - k8s.container
  selector:
    - "status:CLOSE_WAIT"
```

TODO: This is not totally clear how this should work since there gadget doesn't provide a stream of
events. In this case we should execute the gadget each time prometheus scrapes the endpoint.

### Histograms

The histogram definition is a bit more complex than the previous ones, hence please check the Prometheus
documentation:
[https://prometheus.io/docs/concepts/metric_types/#histogram](https://prometheus.io/docs/concepts/metric_types/#histogram)

We'll support the same bucket configuration as described in
[https://github.com/cloudflare/ebpf_exporter#histograms.](https://github.com/cloudflare/ebpf_exporter#histograms.)

```yaml
# DNS replies latency
- name: dns_latency
  type: histogram
  category: trace
  gadget: dns
  field: latency
  bucket:
    min: 0s
    max: 1m
    type: exp2
  labels:
    - k8s.namespace
    - k8s.pod
  selector:
    - "qr:R"
```

# Implementation

## Gadgets supported

We want to make Prometheus supported by as many gadgets as possible, however it's currently not
possible to support all of them. The initial implementation covers these gadgets:

- Tracers: counters and histograms
- Snapshot: gauges

There are some categories that we don't know if they can be supported altogether, so we probably should
also define per gadget support:

- Audit seccomp: counters
- Profile block-io: will be nice but can require some extra work

## Metrics collection

The main implementation detail of this support is where to count the metrics. This proposal includes
two approaches that are independent and that can be implemented in parallel or one after the other:

- Collect metrics in user space: A very flexible and less performant solution
- Collect metrics in eBPF: A more performant solution that should handle most common metrics

### Collection in user space

In this case the counting / aggregation happens on user space. This is the simplest way to collect
metrics, but also the most expensive one. It leverages the whole functionality of our gadgets as it
is right now. Events are still collected in eBPF and sent to user-space as they occur, where they
are evaluated, i.e., aggregated and filtered according to the user's configuration.

This option is defined to be flexible rather than performant. For metrics with high throughput, users should use
the metrics collection backed by eBPF (see below).

The implementation is based on the existing parser that uses reflection underneath, a PoC is
implemented in
[https://github.com/inspektor-gadget/inspektor-gadget/tree/mauricio/experiments/prometheus](https://github.com/inspektor-gadget/inspektor-gadget/tree/mauricio/experiments/prometheus)

### Collection in eBPF

We should extend the gadgets to collect some common metrics in eBPF to make this solution more
performant. This should be the preferred way of collecting metrics, even if it isn't as flexible as
the implementation using the events (and it's harder to implement). In this case, we'll have to define a
list of common metrics that are exposed by each gadget (TODO).

Gadgets' eBPF code would require two new constants:

```c
bool enable_events
bool enable_metrics
```

When metric collection is enabled, it expects maps that it can fill. The gadget/operator will provide such
maps with a layout depending on the users' configuration.

The biggest issue here is that we basically need to have counters for each of the possible tuples of
the requested labels (which are dynamic). This would be solved by a BPF_HASH_MAP (potentially
PER_CPU) with the key looking like this for example:

```c
struct metric_key_t {
__u64 mount_ns_id;
__u32 reason;
}
```

With each added label, the key length increases. Adding for example the SADDR, the key would look
like this:

```c
struct metric_key_t {
__u64 mount_ns_id;
__u8 saddr[16];
__u32 reason;
}
```

The actual value consists of a simpler struct, containing for example just a counter variable,
buckets for histograms, etc. (and maybe a last-access timestamp).

The operator would then periodically iterate over the map and update the exported metrics.

We'd have to think about pruning the maps periodically as well, otherwise the maps would only grow -
the mentioned timestamp could help with that. We also have to notify the user about possible
overflows.

#### Use of Macros

To be able to use maps like described above, the keys of the maps would have to be sized
dynamically. This can be achieved by using macros and consts that switch on/off certain fields on
demand (I've started work on a PoC).

A definition like this

```c
#define METRIC_LIST_KEYS(X) \
 X(MntNS, __u64, 8) \
 X(Reason, __u32, 4)
```

could then create required functions (like offset helpers) and volatile consts that will be set upon
starting the gadget.

# Compatibility with script and BYOB (bring your own bpf) gadgets

These two gadgets allow the user to inject custom eBPF programs. It should be possible to
also support metric collection using this solution. The structure of the eBPF maps that collect the
metrics should be well defined to create a contract between the eBPF programs and the
Operator/Gadget in user space.

## BYOB

We have to document what is the structure of the maps and the user will be responsible for creating
and filling them in their eBPF programs

## Script

This gadget creates the eBPF maps on behalf of users when they specify they want a counter. We will
need to be sure those maps stick to the contract defined above. The syntax to defining counters,
histograms, etc by using the DSL can be very similar to what we already have in bpftrace
[https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md#2-count-count](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md#2-count-count),
[https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md#8-hist-log2-histogram](https://github.com/iovisor/bpftrace/blob/master/docs/reference_guide.md#8-hist-log2-histogram).

# Out of Scope

- Providing a Golang package for 3rd party applications: This solution will be implemented as a
  Gadget/Operator, hence it'll also be available for 3rd party applications. It's not on our roadmap
  to provide a golang package supporting this, however it should be easy to refactor the code
  and create such a package if needed in the future. At that point we'll need to determine the
  format used by this package to expose the data. One possibility is to expose Otel metrics and the
  user then will convert them to the needed format, Prometheus for instance.