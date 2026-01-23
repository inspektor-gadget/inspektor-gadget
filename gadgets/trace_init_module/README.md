# trace_init_module

The trace_init_module gadget emits events when processes invoke the `init_module(module_image, len, param_values)` syscall to load kernel modules.

It captures:

- `len` (module image length in bytes)
- `param_values` (module parameters as a userspace string, truncated to 256 bytes for safety)
- common process context fields (comm/pid/tid, uid/gid, etc.)

**Note:** The `module_image` pointer is not captured (it points to a potentially large binary blob).

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/trace_init_module
