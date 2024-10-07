---
title: CLI
---

The CLI operator is the default output operator - it prints all information and
data from a gadget to the standard output (usually your terminal). It supports
different output formats, depending on the gadget and the use case.

## Priority

10000

## Parameters

### Instance Parameters

### `fields`

Set the fields to be printed. Multiple data sources and fields can be specified
using the format
`datasource:comma,separated,fields;datasource2:comma,separated,fields`.

Fully qualified name: `operator.cli.fields`

### `output`

Determines the output format for the data source. The following modes are
supported:

- `columns`: This is the default output mode. It displays the output in a
  tabular format with a column for each field in the data source, unless the
  field is annotated with `columns.hidden: true`. In addition to hiding columns,
  you can also customize the columns format by using several annotations like
  `columns.width`, `columns.alignment`, etc., as explained in TODO.
- `json`: This mode displays the output in JSON format. Note that the output
  contains all the fields of the data source, even if they annotated with
  `columns.hidden: true` as this annotation applies only to the `columns` mode.
  Depending on the data source type, it may be an array of objects or multiple
  objects separated by newlines.
- `jsonpretty`: As the `json` mode, but the output is formatted in a more
  human-readable way.
- `yaml`: This mode displays the output in YAML format. Like the `json` mode, it
  contains all the fields of the data source. YAML entries will be separated by
  `---` to make it easier to read.
- `none`: This mode does not display any output.
- `raw`: This mode displays the raw data output. This is useful when you don't
  want the output to be formatted in any way, maybe because you want to pipe it
  to another tool or because it's already formatted in the way you want.

By default, the CLI operator allows displaying the output of each data source in
all the supported output modes. However, you can customize the supported output
modes of your data sources by setting the
[supported-output-modes](#supported-output-modes) annotation.

Fully qualified name: `operator.cli.output`

Default: `columns`

## Annotations

The following annotations can be used to control the behaviour of the CLI
operator for the data source they are applied to.

### `clear-screen-before`

Clear the screen before printing the output of the data source. This is useful
when for array data sources that periodically emit an array of objects and you
want to clear the screen before printing the batch of objects.

This annotation is only applicable to the `columns` and `raw` output modes.

Fully qualified name: `operator.cli.clear-screen-before`

### `supported-output-modes`

Coma-separated list of output modes supported for the data source. This is useful
when you want to restrict the output modes for a data source.

Fully qualified name: `operator.cli.supported-output-modes`
