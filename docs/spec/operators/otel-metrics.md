---
title: otel-metrics
---

The otel-metrics operator handles collecting and exporting metrics using the
[Prometheus exporter](https://opentelemetry.io/docs/specs/otel/metrics/sdk_exporters/prometheus/). When setting
`otel-metrics-listen=true`, it will serve http requests on "0.0.0.0:2224" (configurable using
`otel-metrics-listen-address`) with the metrics available at "/metrics".

## Priority

9995

## Global Parameters

### `otel-metrics-listen`

Enables the Prometheus exporter on the address given by `otel-metrics-listen-address` if set to `true`.

Default: `false`

## Instance Parameters

The listen address that should be serving Prometheus requests.

Default: `0.0.0.0:2224`

## Instance Parameters

### `otel-metrics-name`

Overrides the name of a datasource and explicitly sets it as name for the export. This is mandatory if you
want to export the metrics. Use a name that is unique to the gadget+params combination to avoid collision of metrics.

### `otel-metrics-print-interval`

Interval in which metrics should be emitted as human-readable text. This only has effect for data sources that are
annotated using `metrics.print=true`. This is also limited to print histograms for now. This functionality might be
removed in the future.

Default: `1000ms`
