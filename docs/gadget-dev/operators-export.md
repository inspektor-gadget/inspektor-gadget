---
title: Built-in operators for export
description: >
  This section contains information on built-in operators that can
  be used to export or print data.
weight: 200
---

## cli

The CLI operator prints data from Data Sources. It is enabled by
default. Currently, it can print data in column-mode (table-like)
directly to stdout or as newline-terminated JSON/YAML encoded data.

### Used Annotations

#### Field Annotations

| Annotation  | Description                                                                  | Default |
|-------------|------------------------------------------------------------------------------|---------|
| description | Textual description of the field; will be used in the field listing (--help) |         | 

## otel-metrics

The otel-metrics operator exposes data sources to a built-in metrics
endpoint that you can use to collect metrics from for example Prometheus.

To export a data source as OpenTelemetry metrics, you have to enable it by
setting the `metrics.export: true` annotation on the data source.

You also have to add at least the `metrics.type` annotation to fields for them to be exported. Either
specify `counter`, `gauge` or `histogram` (fields must be numeric) to use that specific type; or use
`key` to use the field as label to group metrics by (for example a node name, a process name or similar).

For more information see the OpenTelemetry documentation [here](https://opentelemetry.io/docs/specs/otel/metrics/data-model/).

### Used Annotations

#### DataSource annotations

| Annotation     | Description                                                          | Default |
|----------------|----------------------------------------------------------------------|---------|
| metrics.export | Defines whether the data source should be considered by the operator | false   |

#### Field annotations

| Annotation          | Description                                                                                                                            | Default |
|---------------------|----------------------------------------------------------------------------------------------------------------------------------------|---------|
| metrics.type        | Defines the type of metric: "counter", "gauge", "histogram"; "key" is used to group metrics                                            |         |
| metrics.description | A description that also gets exported as description for the metric                                                                    |         |
| metrics.unit        | The unit used by the metric (see https://unitsofmeasure.org/ucum)                                                                      |         |
| metrics.boundaries  | histogram only: comma-separated list of bucket boundaries (see https://opentelemetry.io/docs/specs/otel/metrics/data-model/#histogram) |         | 
