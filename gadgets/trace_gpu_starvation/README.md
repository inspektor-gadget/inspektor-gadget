# trace_gpu_starvation

`trace_gpu_starvation` detects threads that burn CPU while the GPU their
process owns sits idle, and captures the responsible call stack. It
combines the per-process GPU metrics published by the
[gpu-ebpf-bridge](https://inspektor-gadget.io/docs/latest/reference/gpu-ebpf-bridge) daemon with a
`finish_task_switch` scheduler kprobe, so it attributes the wasted CPU to
the exact thread and stack keeping the GPU starved.

Because GPU idleness comes from NVML hardware SM counters (not CPU-side
inference), the gadget is not fooled by asynchronous CUDA launches.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/trace_gpu_starvation.
