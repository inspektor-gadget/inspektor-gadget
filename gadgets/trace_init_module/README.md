# trace_init_module

The trace_init_module gadget emits events when processes invoke the `init_module()` or `finit_module()` syscalls to load kernel modules.

**Syscalls traced:**
- `init_module(module_image, len, param_values)` - loads a module from a memory buffer
- `finit_module(fd, param_values, flags)` - loads a module from a file descriptor

It captures:

For `init_module`:
- `len` (module image length in bytes)
- `param_values` (module parameters)

For `finit_module`:
- `fd` (file descriptor)
- `filepath` (resolved from fd when possible. Empty when fd pointing to memory.)
- `flags` (finit_module flags)
- `param_values` (module parameters)

**Common fields:**
- Process context (comm/pid/tid, uid/gid, etc.)
- `syscall` field to distinguish between init_module and finit_module

**Note:** The `module_image` buffer from `init_module` is not captured. Parameter strings are truncated to 256 bytes.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/trace_init_module
