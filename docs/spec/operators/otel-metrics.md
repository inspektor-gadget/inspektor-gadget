---
title: otel-metrics
---

The otel-metrics operator handles collecting and exporting metrics using the
[Prometheus exporter](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/prometheus/). When setting
`otel-metrics-listen=true`, it will serve http requests on "0.0.0.0:2224" (configurable using
`otel-metrics-listen-address`) with the metrics available at "/metrics".

## Priority

9995

## Parameters

### Global Parameters

> Most of these settings only apply to a locally created metric endpoint (Prometheus compatible). If
> you want to export metrics using other protocols, please check the documentation about
> [Other Exporters](../../reference/export-metrics.mdx#other-exporters).

#### `otel-metrics-listen`

Enables the Prometheus exporter on the address given by `otel-metrics-listen-address` if set to `true`.

Default: `false`

#### `otel-metrics-listen-address`

The listen address that should be serving Prometheus requests.

Default: `0.0.0.0:2224`

#### `otel-metrics-export-internals`

Enables exporting internal Inspektor Gadget metrics to the global exporter that is
configured using `otel-metrics-listen`.

Default: `false`

### Instance Parameters

#### `otel-metrics-name`

Overrides the name of a datasource and explicitly sets it as name for the export. This is mandatory if you
want to export the metrics. Use a name that is unique to the gadget+params combination to avoid collision of metrics.

Fully qualified name: `operator.otel-metrics.otel-metrics-name`

#### `otel-metrics-print-interval`

Interval in which metrics should be emitted as human-readable text. This only has effect for data sources that are
annotated using `metrics.print=true`. This is also limited to print histograms for now. This functionality might be
removed in the future.
The minimum interval is 25ms.

Fully qualified name: `operator.otel-metrics.otel-metrics-print-interval`

Default: `1000ms`

## Annotations

### Data Source Annotations

#### `metrics.collect`

Together with the `otel-metrics-listen=true` and `otel-metrics-name=<name>`
flags, this annotation is used to enable the Otel Metrics operator to export the
data source's output as Prometheus metrics.

#### `metrics.snapshot`

Controls whether gauge series are collected as snapshots. By default, gauges
are recorded synchronously and retain the latest value for each attribute set.

Set this annotation to `true` when every array emitted by the data source is
a complete refresh of the currently active entities:

```yaml
datasources:
  metrics:
    annotations:
      metrics.collect: "true"
      metrics.snapshot: "true"
```

Snapshot mode uses observable gauges. Each emitted array atomically replaces
the previous gauge snapshot, so attribute sets omitted from a later array are
no longer exported. An empty array removes all gauge series for the data source.
Snapshot mode is only supported for array data sources.

Counters and histograms in the same data source retain their normal cumulative
behavior. Snapshot replacement only applies to fields with
`metrics.type=gauge`.

Rows within one snapshot must have unique values for the fields annotated with
`metrics.type=key`. The operator rejects a snapshot containing duplicate key
sets instead of applying an implicit last-write-wins aggregation. A rejected
snapshot does not replace the previous gauge snapshot; the rows remain
available to other operators, and counters and histograms still consume them.

#### `metrics.snapshot-timeout`

Sets how long the latest snapshot remains authoritative without another
completed refresh. When the timeout expires, the observable callback stops
exporting all gauges from that snapshot.

If omitted, the timeout defaults to three times the data source's positive
`fetch-interval`. Data sources without a positive fetch interval must configure
the timeout explicitly. An explicit timeout must be at least twice the positive
`fetch-interval`. Prefer the derived timeout when users can override the fetch
interval.

```yaml
datasources:
  metrics:
    annotations:
      metrics.snapshot: "true"
      metrics.snapshot-timeout: 5s
```

An empty snapshot removes series immediately. The timeout instead covers a
stalled data source that stops emitting refreshes.

#### `metrics.print`

If set to `"true"`, the Otel Metrics operator will render the data source's
output in more human-friendly formats.

Currently, this feature only supports rendering as histograms the output of [Map
Iterators](../../gadget-devel/gadget-intro.md#map-iterators) with the map’s
value type of `gadget_histogram_slot__u32` or `gadget_histogram_slot__u64`
(TODO: Add link). To achieve this, the Otel Metrics operator disables the
original data source and creates a new one, suffixed with `-rendered`, which
will emit the original data source's output as a rendered histogram.
Additionally, the Otel Metrics operator will configure the CLI operator for this
new data source as follows:

- Set both the [cli.supported-output-modes](./cli.md#clisupported-output-modes)
  and [cli.default-output-mode](./cli.md#clidefault-output-mode) annotations to
  `histogram`. This will create a custom output mode that will make the CLI
  operator print the output as it is received (i.e., a rendered histogram), and
  use this mode as the default.
- Set the [cli.clear-screen-before](./cli.md#cliclear-screen-before) annotation
  to `true` to make the CLI operator clear the screen before printing each
  histogram.

### Field Annotations

#### `metrics.type`

Defines the type of the field. If not set, the operator will try to infer it
from the field type.

Possible values: `counter`, `gauge`, `histogram`, `key`.

#### `metrics.unit`

This annotation is used to set the [OpenTelemetry instrument
unit](https://pkg.go.dev/go.opentelemetry.io/otel/metric@v1.30.0#WithUnit). It
should be defined using the appropriate [UCUM](https://ucum.org) case-sensitive
code.

#### `metrics.description`

This annotation is used to set the [OpenTelemetry instrument
description](https://pkg.go.dev/go.opentelemetry.io/otel/metric@v1.30.0#WithDescription).

#### `metrics.boundaries`

For fields of type `histogram`, this annotation allows to specify the
[OpenTelemetry instrument explicit bucket
boundaries](https://pkg.go.dev/go.opentelemetry.io/otel/metric@v1.30.0#WithExplicitBucketBoundaries).
It should be a comma-separated list of numbers.
