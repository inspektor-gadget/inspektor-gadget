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

#### `fields`

Set the fields to be printed. Multiple data sources and fields can be specified
using the format
`datasource:comma,separated,fields;datasource2:comma,separated,fields`.

Fully qualified name: `operator.cli.fields`

#### `output`

Determines the output format of the data source. It can be either a single output
mode for all data sources or an output mode for each data source individually in
the format `datasource:mode,datasource2:mode`.

The following modes are supported:

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

By default, the CLI operator allows setting the output of each data source in
all the supported modes. However, this can be customized by annotating the data
source with the [supported-output-modes](#clisupported-output-modes) annotation.

Also, you can change the default output mode for each data source by setting the
[default-output-mode](#clidefault-output-mode) annotation.

Fully qualified name: `operator.cli.output`

Default: `columns`

## Annotations

### Data Source Annotations

#### `cli.supported-output-modes`

Comma-separated list of output modes supported for the data source. This is
useful when you want to customize the output modes supported by the data source.

Note that if you include any output mode different from the ones supported by
the CLI operator, it will treat as a custom output mode and will be printed as a
string.

#### `cli.default-output-mode`

Set the default output mode for the data source. This is useful when you want to
set a different default output mode for a data source.

#### `cli.clear-screen-before`

Clear the screen before printing the output of the data source. This is useful
for data sources that emit periodically the batch of data and you want to clear
the screen before printing the new data.

This annotation is only applicable to the `columns` and custom output modes
added by annotating the data source with `cli.supported-output-modes`.
