---
title: CLI
---

The CLI operator prints information to the terminal. When using `gadgetctl` or
`kubectl-gadget`, this opereator takes the data coming from the server and
prints it to the terminal.

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
