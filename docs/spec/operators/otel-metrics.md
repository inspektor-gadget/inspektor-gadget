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

#### `otel-metrics-listen`

Enables the Prometheus exporter on the address given by `otel-metrics-listen-address` if set to `true`.

Default: `false`

#### `otel-metrics-listen-address`

The listen address that should be serving Prometheus requests.

Default: `0.0.0.0:2224`

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
