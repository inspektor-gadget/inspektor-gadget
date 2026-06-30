# gpu_top_per_pid

`gpu_top_per_pid` shows per-process GPU usage (VRAM, peak SM and memory
utilization, device count) published by the
[gpu-ebpf-bridge](https://github.com/alban/gpu-ebpf-bridge) daemon.
Events are automatically enriched with comm, container, pod, and K8s
context via Inspektor Gadget's standard enrichers.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/gpu_top_per_pid.
