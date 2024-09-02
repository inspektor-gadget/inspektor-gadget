---
title: CLI
---

The CLI operator is the default output operator - it prints all information and
data from a gadget to the standard output (usually your terminal). It supports
different output formats, depending on the gadget and the use case.

## Priority

10000

## Instance Parameters

### `fields`

Set the fields to be printed. Multiple data sources and fields can be specified
using the format
`datasource:comma,separated,fields;datasource2:comma,separated,fields`.

Fully qualified name: `operators.cli.fields`

### `mode`

Determines the output format:
- `json`: Outputs in JSON format.
- `jsonpretty`: Outputs in pretty-printed JSON format.
- `columns`: Outputs in a columnar format.
- `yaml`: Outputs in YAML format.
- `none`: No output.
- `raw`: Outputs raw data.

Fully qualified name: `operators.cli.mode`

Default: `columns`
