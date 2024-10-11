---
title: 'Displaying Output'
sidebar_position: 620
---

By default, Inspektor Gadget allows you to display the output of each data
source in all the output modes supported by the [CLI
operator](../spec/operators/cli.md#output). Unless you have specific
requirements, we recommend using the CLI operator's default configuration.
However, for [Map Iterators](./gadget-intro.md#map-iterators) with a map value
type of `gadget_histogram_slot__u32` or `gadget_histogram_slot__u64` (TODO: Add
links), the output should be displayed as a chart, which the CLI operator
doesn't support. In such cases, you can use the [Otel
Metrics](../spec/operators/otel-metrics.md) operator to render the output as a
histogram by annotating the data source with [metrics.print:
"true"](../spec/operators/otel-metrics.md#metricsprint). The
[profile_blockio](../gadgets/profile_blockio.mdx) gadget is an example of this.

## Fields

The fields to be displayed in the output when using the `columns`, `json`,
`jsonpretty` or `yaml` output modes depend on the data source type:

- Tracers: The fields are all the elements of the event `struct` specified when
  defining the data source.
- Map Iterators: The fields are all the elements of the key and value `struct`s
  used to define the eBPF map to be iterated. As mentioned above, there is a
  special case for the map iterators with a map value type of
  `gadget_histogram_slot__u32` or `gadget_histogram_slot__u64`. In such cases,
  the data source created by the Otel Metrics operator will contain just one
  field called `text` which will carry the rendered histogram as a plain text.
- Snapshotters: The fields are all the elements of the snapshot entry `struct`
  specified when defining the data source.
