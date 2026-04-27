---
title: logs
---

The logs operator writes gadget data events to a persistent log stream (stderr, stdout, or a file). Each event is
wrapped in an envelope containing metadata (gadget name, datasource, timestamp, sequence number). It supports JSON and
logfmt output formats, file rotation via [lumberjack](https://pkg.go.dev/gopkg.in/natefinch/lumberjack.v2), and
SIGHUP-triggered
rotation.

This operator is only active on the server side (remote/daemon runs). For local CLI runs, the
[CLI operator](cli.md) handles output instead.

## Priority

9998

## Configuration

The logs operator is configured through the Inspektor Gadget configuration file:

```yaml
operator:
  logs:
    enabled: true
    channel: file
    filename: /var/log/ig/gadget.log
    format: json
    mode: all
    max-size-mb: 100
    max-age-days: 7
    max-backups: 3
    compress: true
```

### Configuration Parameters

#### `operator.logs.enabled`

Enables or disables the logs operator.

Default: `false`

#### `operator.logs.channel`

The output channel for log events.

- `stderr`: Write to standard error (default)
- `stdout`: Write to standard output
- `file`: Write to a file specified by `operator.logs.filename`

Default: `stderr`

#### `operator.logs.format`

The output format for log events.

- `json`: NDJSON format with a structured envelope (default)
- `logfmt`: Key-value pairs in logfmt format

Default: `json`

#### `operator.logs.mode`

Controls which gadget instances are logged.

- `all`: Log events from all gadget instances (default)
- `detached`: Only log events from detached (background) gadget instances

Default: `all`

#### `operator.logs.filename`

The path to the log file. Required when `channel` is `file`.

#### `operator.logs.max-size-mb`

Maximum size in megabytes of a log file before rotation. Rotating by size cannot be disabled.

Default: `100`

#### `operator.logs.max-backups`

Number of rotated log files to keep. `0` means keep all rotated files.

Default: `3`

#### `operator.logs.max-age-days`

Maximum age in days of rotated log files before deletion. `0` means never delete based on age.

Default: `0`

#### `operator.logs.compress`

Whether to compress rotated log files using gzip.

Default: `false`

## Annotations

### Data Source Annotations

#### `logs.array-handling`

Controls how `TypeArray` datasources are emitted in JSON format. This annotation
is set by gadget authors on a datasource.

- `array`: Emit a single log line with `"data"` as a JSON array (default)
- `elements`: Fan out into individual log lines per array element, all sharing
  the same `seq` number

This annotation has no effect on `logfmt` format, which always fans out array
elements into individual lines.

## Output Format

### JSON

Each event is emitted as a single NDJSON line with the following envelope:

```json
{
  "type": "gadget-data",
  "seq": 0,
  "gadget": "trace_open",
  "datasource": "events",
  "instanceID": "abc123",
  "timestamp": "2026-04-01T12:00:00.000Z",
  "data": {
    ...
  }
}
```

#### Envelope Fields

| Field        | Type            | Description                                                                                                                                                            |
|--------------|-----------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `type`       | string          | `gadget-data` for events with data, `gadget-data-empty` for empty array emissions. Distinguishes from log messages (`gadget-log`).                                     |
| `seq`        | number          | Per-datasource sequence number, starting at 0. Increments for each emission. Can be used to detect gaps.                                                               |
| `gadget`     | string          | The gadget name.                                                                                                                                                       |
| `datasource` | string          | The datasource name.                                                                                                                                                   |
| `instanceID` | string          | The gadget instance ID. Omitted when empty.                                                                                                                            |
| `timestamp`  | string          | RFC3339Nano UTC timestamp of when the event was logged.                                                                                                                |
| `data`       | object or array | The gadget data. An object for single events, an array for `TypeArray` datasources (unless `logs.array-handling=elements`). Absent when `type` is `gadget-data-empty`. |

#### Empty array emissions

When a `TypeArray` datasource emits an empty array, a single line is emitted with `"type":"gadget-data-empty"` and
no `"data"` field. The `seq` counter is still incremented so consumers can detect the emission.

```jsonnd
{"type":"gadget-data-empty","seq":2,"gadget":"snapshot_process","datasource":"procs","timestamp":"..."}
```

#### TypeArray with default handling (`array`)

A single line with `"data"` as an array:

```jsonnd
{"type":"gadget-data","seq":0,"gadget":"snapshot_process","datasource":"procs","timestamp":"...","data":[{"name":"nginx","pid":100},{"name":"bash","pid":200}]}
```

#### TypeArray with `logs.array-handling=elements`

Multiple lines with the same `seq`, each with `"data"` as an object:

```jsonnd
{"type":"gadget-data","seq":0,"gadget":"snapshot_process","datasource":"procs","timestamp":"...","data":{"name":"nginx","pid":100}}
{"type":"gadget-data","seq":0,"gadget":"snapshot_process","datasource":"procs","timestamp":"...","data":{"name":"bash","pid":200}}
```

### Logfmt

Each event is emitted as a single logfmt line:

```
type=gadget-data seq=0 gadget=trace_open datasource=events instanceID=abc123 timestamp=2026-04-01T12:00:00.000Z pid=1234 comm=nginx
```

For `TypeArray` datasources, each element is emitted as a separate line sharing the same `seq`:

```
type=gadget-data seq=0 gadget=snapshot_process datasource=procs timestamp=... name=nginx pid=100
type=gadget-data seq=0 gadget=snapshot_process datasource=procs timestamp=... name=bash pid=200
```

Empty array emissions use `type=gadget-data-empty` with no data fields:

```
type=gadget-data-empty seq=2 gadget=snapshot_process datasource=procs timestamp=...
```

Values containing spaces, double quotes, or `=` are quoted. Control characters are escaped.

## Log Rotation

When `channel` is `file`, the operator uses lumberjack for size-based rotation.
Sending `SIGHUP` to the process triggers an immediate rotation, following the
convention used by nginx and syslog-ng.

## Example Usage

### Log all gadget data to stderr in JSON format

```yaml
operator:
  logs:
    enabled: true
```

### Log detached gadgets to a rotated file

```yaml
operator:
  logs:
    enabled: true
    channel: file
    filename: /var/log/ig/gadget.log
    mode: detached
    max-size-mb: 50
    max-backups: 5
    max-age-days: 30
    compress: true
```

### Log in logfmt format to stdout

```yaml
operator:
  logs:
    enabled: true
    channel: stdout
    format: logfmt
```
