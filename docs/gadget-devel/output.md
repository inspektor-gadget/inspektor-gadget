---
title: 'Displaying Output'
sidebar_position: 620
---

By default, Inspektor Gadget allows you to display the output of each data
source in all the output modes supported by the [CLI
operator](../spec/operators/cli.md#output). However, some of them may not be
suitable for your gadget depending on the [data source
types](./gadget-intro.md#data-sources-types) it uses. So, you can customize the
supported output modes and default output mode for each data source by ...
TODO: Allow customizing the output modes and default output mode for each data.

Unless you have specific requirements do otherwise, we recommend using the
default supported output modes and the default output mode for all data sources
except for [Profilers](./gadget-intro.md#profilers). It's because, for now,
profilers only support `raw` output mode as they use the [Otel
Metrics](../spec/operators/otel-metrics.md) operator to render the output in a
more user-friendly way, e.g., histograms. To do so, the Otel Metrics operator
disables the original profiler data source and creates a new one suffixed with
`-rendered` that emits the output only in `raw` mode. So, unless you have
specific requirements do otherwise, we recommend letting the Otel Metrics
operator handle the CLI configuration for profilers.

## Fields

The fields to be displayed in the output when using the `columns`, `json`,
`jsonpretty` or `yaml` output modes depend on the data source type:

- Tracers: The fields are all the elements of the event `struct` specified when
  defining the data source.
- Map Iterators: The fields are all the elements of the key and value `struct`s
  used to define the eBPF map to be iterated.
- Snapshotters: The fields are all the elements of the snapshot entry `struct`
  specified when defining the data source.
- Profilers: As mentioned above, this is a special case. The data source created
  by the Otel Metrics operator will contain just one field called `text` with
  the raw rendered output of the profiler data source.
