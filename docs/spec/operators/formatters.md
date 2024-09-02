---
title: Formatters
---

The Formatters operator provides a human readable representation of things like
IP addresses, signal names, error names, etc. Gadgets provide a "machine
readable" version and then the operator adds the human readable counterpart:

## Timestamp

```json
  "timestamp": "2024-08-27T11:29:02.846074392-05:00",
  "timestamp_raw": 1724776142846074400,
```

## Error

```json
  "error": "ENOENT",
  "error_raw": 2,
```

## Signal

```json
  "sig": "SIGURG",
  "sig_raw": 23,
```

## Syscalls

```json
  "syscall": "SYS_SOCKET",
  "syscall_raw": 41,
```

## IP Addresses

```json
  "src": {
    "addr": "172.17.0.2",
    "version": 4
  },
```

## TCP and UDP endpoints

```json
  "src": {
    "addr": "172.17.0.2",
    "port": 46076,
    "proto": 6,
    "version": 4
  },
```

Please check the [gadget developer
documentation](../../gadget-devel/gadget-ebpf-api.md#enriched-types) to learn
how to use this operator in your gadget.

## Priority

0

## Parameters

None
