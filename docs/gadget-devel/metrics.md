---
title: 'Adding Metrics to your Gadget'
sidebar_position: 500
---

> These instructions explain how to implement metrics collection if you're developing your own or extending an existing
> gadget. For the user perspective of things (actually exporting the metrics to a third party), please read
> this (TODO).

Inspektor Gadget allows you to easily add metrics to your gadgets that then can be exported to OpenTelemetry compatible
software (like Prometheus), the CLI, or other third parties by implementing a dedicated operator for that.

Inspektor Gadget currently supports counters, gauges and histograms - fields must be of any integer or float type. For
histograms, we also support handing over all buckets at once as an array of int32 or int64 and adding their values up.

Metrics can either be collected in user-space or directly inside your eBPF programs using eBPF maps. Which option you
choose depends on how you collect the data and the quantity of it.

If you're sending events to user-space, you can create metrics from those by just adding a couple of annotations to your
`gadget.yaml` file, or by using some well-known types (TODO links to macros) inside your struct definition inside eBPF code.

If you don't want to emit events, because it would just be too much throughput, you can choose to write the metrics into
eBPF maps instead and let IG create a data source (TODO link to data source) from it. Those can then be
exported to for example Prometheus.

| Source     | Application                                                                             | Performance |
|------------|-----------------------------------------------------------------------------------------|-------------|
| user-space | easy development when using event sources (GADGET_TRACE()); event sources can be reused | slower      |
| eBPF maps  | using dedicated maps for metrics, especially suited for high throughput scenarios       | fast        |

## User-space collection

### Using the metadata file

Without modifying eBPF code, you can modify the `gadget.yaml` to specify how metrics should be collected from existing
data sources. Keep in mind that this requires an event being sent to user-space in order to work - so if you expect
many events, please look into implementing the metrics collection using eBPF maps (see below).

Let's assume you've already got a data source called `events`. That data source has two fields - a string field called
`name` and an int32 field called `count`. The (empty) section of your `gadget.yaml` file for that datasource could look
like this:

```yaml
datasources:
  events:
    fields:
      name:
      count:
```

First, you need to annotate the data source itself with `metrics.collect` set to `true`.

Now, if you want to expose the field `count` as a metric, just annotate the field with `metrics.type` as key and `counter`
as value, like so:

```yaml
datasources:
  events:
    annotations:
      metrics.collect: true
    fields:
      count:
        annotations:
          metrics.type: counter
```

This will increase the counter of that metrics by whatever value the `count` field has. Use `metrics.type: gauge`, if
you always just want to set the metric to the latest value.

If you later on want to differentiate the count by their different `name` contents, you can annotate the `name` field
with key `metrics.type` and value `key`. This creates a key (or label) from that field that is associated with each
metric afterward - e.g.: this lets you later on filter the values of `count` according to the corresponding `name`
values.

> Note: adding multiple metric.key annotations will increase cardinality a lot and take up more space and storage.

### Using well-known types in the eBPF code

You can also edit your eBPF source code and use well-known types (TODO links to well known types) instead of annotating
the individual fields. An event struct using this could look like:

```c
struct event {
	...
	gadget_counter__u32 name;
	...
}
```

## Collection of metrics from eBPF maps

The following instructions expect you to collect metrics in an eBPF map that is periodically read into Inspektor Gadget.
This is the preferred way to collect metrics in high throughput scenarios - like when registering metrics from network
packets or other kernel hooks in a hot path or without strict filtering.

We use eBPF hash maps like this (this example is following a similar structure as the user-space collection example
above):

```c
...
#include <gadget/macros.h>
...

#define MAX_ENTRIES 10240

struct metrics_key {
	__u32 key;
};

struct metrics_value {
	gadget_counter__u32 counter;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, struct metrics_key);
	__type(value, struct metrics_value);
} metrics SEC(".maps");

GADGET_MAPITER(mymetrics, metrics);
```

Let's quickly go through what happens here, from bottom to top:

`GADGET_MAPITER(mymetrics, metrics);` registers a map iterator called `mymetrics` (this will be the name of the
data source later on) for the map `metrics` defined above. That map is of type `BPF_MAP_TYPE_HASH` and uses
`struct metrics_key` as its key and `struct metrics_value` as its value types respectively.

If you look at the `struct metrics_value` definition, you see one field of type `gadget_counter__u32`. This will tell
IG that this value is meant to be registered as a `counter` of type `__u32`. All members of `struct metrics_value` will
be registered as `keys` (labels).

You can fill the map like you usually would (e.g. using `bpf_map_update_elem`, `bpf_map_lookup_elem` and so on), but
you still need to annotate the data source with key `metrics.collect` and value `true` like so:

```yaml
datasources:
  metrics:
    annotations:
      metrics.collect: true
```

> TODO: more details on histograms
