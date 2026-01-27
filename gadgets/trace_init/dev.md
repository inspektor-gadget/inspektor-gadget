# Developer Notes

This file complements the README file with implementation details specific to this gadget.

## Overview

The `trace_init` gadget uses the syscall tracepoint:

- `tracepoint/syscalls/sys_enter_init_module` to capture syscall arguments and emit the event

To regenerate the interaction diagrams, run:

```bash
make -C gadgets trace_init/dev.md
```
