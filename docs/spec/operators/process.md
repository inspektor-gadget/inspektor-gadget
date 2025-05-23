---
title: process
---

The process operator emits events about running processes with CPU and RAM usage information. It periodically collects information about running processes and emits them as events through a data source.

## Priority

0

## Configuration

The process operator is configured through the gadget.yaml file using the following configuration:

```yaml
internalDataSources:
  processes:
    enabled: true
    interval: 60s
    fields:
    - comm
    - pid
    - ppid
    - cpuUsage
    - cpuUsageRelative
    - memoryRSS
    - memoryVirtual
    - memoryRelative
    - threadCount
    - state
    - uid
    - startTime
```

### Configuration Parameters

#### `internalDataSources.processes.enabled`

Enables or disables the process monitoring. When set to `true`, the operator will start collecting and emitting process information.

Default: `false`

#### `internalDataSources.processes.interval`

The interval at which process information is collected and emitted. This should be a valid duration string (e.g., "60s", "1m", "5m").

Default: `60s`

#### `internalDataSources.processes.fields`

A list of fields to include in the process information. If not specified, all fields will be included. The PID field is always included regardless of this setting.

Available fields:
- `pid` - Process ID (always included)
- `ppid` - Parent Process ID
- `comm` - Command name
- `cpuUsage` - CPU usage percentage
- `cpuUsageRelative` - CPU usage percentage relative to number of CPUs available
- `memoryRSS` - Resident Set Size
- `memoryVirtual` - Virtual memory size
- `memoryRelative` - Total memory used relative to available memory
- `threadCount` - Number of threads
- `state` - Process state
- `uid` - Process owner UID
- `startTime` - Process start time (clock ticks since system boot)
- `startTimeStr` - Process start time as a formatted date-time string (automatically included when startTime is enabled)
- `mountnsid` - Mount namespace ID (always included)

Default: All fields are included

## Data Source

The process operator creates a data source named `processes` that emits events with the following fields:

### Fields

#### `pid`

The process ID.

Type: `int32`

#### `ppid`

The parent process ID.

Type: `int32`

#### `comm`

The command name of the process.

Type: `string`

#### `cpuUsage`

The CPU usage of the process as a percentage.

Type: `float64`

#### `cpuUsageRelative`

The CPU usage percentage relative to the number of CPUs available.

Type: `float64`

#### `memoryRSS`

The Resident Set Size (RSS) of the process in bytes. This represents the portion of memory occupied by a process that is held in main memory (RAM).

Type: `uint64`

#### `memoryVirtual`

The Virtual Memory Size of the process in bytes. This represents the total amount of virtual memory used by the process.

Type: `uint64`

#### `memoryRelative`

Percentage of RSS memory used relative to available memory.

Type: `float64`

#### `threadCount`

The number of threads in the process.

Type: `int32`

#### `state`

The state of the process (e.g., "R" for running, "S" for sleeping, "Z" for zombie, etc.).

Type: `string`

#### `uid`

The UID of the process owner.

Type: `uint32`

#### `startTime`

The time when the process started, represented as clock ticks since system boot.

Type: `uint64`

#### `startTimeStr`

The time when the process started, represented as a formatted date-time string in RFC3339 format (e.g., "2023-06-15T14:30:45Z").
This field is automatically included when the `startTime` field is enabled.

Type: `string`

#### `mountnsid`

The mount namespace ID of the process. This can be used to identify which container a process belongs to.
This field is always included.

Type: `uint64`

## Example Usage

To enable process monitoring, add the following to your gadget.yaml configuration:

```yaml
internalDataSources:
  processes:
    enabled: true
    interval: 30s  # Collect process information every 30 seconds
```

Note that the `mountnsid` field is always included, regardless of the fields configuration.

This will enable the process operator, which will emit process events every 30 seconds with all available fields.

### Example with Selected Fields

To enable process monitoring with only specific fields, add the following to your gadget.yaml configuration:

```yaml
internalDataSources:
  processes:
    enabled: true
    interval: 30s
    fields:
    - comm
    - pid
    - ppid
    - cpuUsage
    - memoryRSS
```

This will enable the process operator, which will emit process events every 30 seconds with only the specified fields. This can be useful to reduce resource usage and network traffic when you only need specific information.
