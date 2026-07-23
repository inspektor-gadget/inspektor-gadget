# GPU-starvation demo workload

A frame-by-frame video-inference workload that reproduces **GPU
starvation** — a process holds GPU memory while the GPU sits idle because
a CPU thread is stuck doing preprocessing. It exercises both
[`trace_gpu_starvation`](../README.md) and
[`profile_cpu --gpu-idle-only`](../../profile_cpu/README.md).

`video_frame_inference.py` has three modes:

| Mode | Behaviour | What the gadget shows |
|---|---|---|
| `bad` | Sequential: CPU preprocess → GPU infer, one frame at a time. GPU idle ~`PREPROCESS_MS` (default 1500 ms)/frame. | Fires; stack points at `cv2.resize` / numpy. |
| `good` | Pipelined with a CUDA stream: CPU preps frame N+1 while GPU runs frame N. GPU is kept busy ~`INFER_MS`/frame. | Stays quiet (control case). |
| `threaded` | A prep thread feeds an inference thread via a queue. | Two stacks: the blocking `queue.get` (inference thread) and `cv2.resize` (prep thread, the real bottleneck). |

`N_FRAMES` (env var) sets how many frames to process; `0` loops forever so
the gadget has time to observe the workload. `PREPROCESS_MS` and `INFER_MS`
(default 1500 ms each) fix the per-frame CPU-preprocess and GPU-inference
time regardless of node speed: the real work is repeated until the budget is
spent, so the GPU-idle stall is deterministic. Keeping `INFER_MS >=
PREPROCESS_MS` is what lets `good` overlap and hide the CPU work — with a
trivial (few-ms) GPU load the GPU would drain in `good` too and both modes
would look starved. `BATCH` (default 64) sizes each inference: it must be
large enough that the GPU kernels are long and high-occupancy, because the
gadget relies on **NVML per-process utilization sampling**, which does not
register short `BATCH=1` kernels — with a tiny batch even a genuinely
GPU-busy `good` run is invisible to NVML and looks starved to the gadget.
The pod manifests default all four.

## Build and push the image

The workload needs a GPU-enabled node, so it is packaged as a container
image and run on the cluster. Set `CONTAINER_REPO` to your registry, then
build and push:

```bash
export CONTAINER_REPO=your-registry.example.com   # e.g. an ACR or ghcr namespace
docker build -t $CONTAINER_REPO/workload/gpu-starvation-demo:latest \
    gadgets/trace_gpu_starvation/demo
docker push $CONTAINER_REPO/workload/gpu-starvation-demo:latest
```

## Run on the cluster

The pod manifest references the image as
`$CONTAINER_REPO/workload/gpu-starvation-demo:latest`. Substitute your
registry (Kubernetes does not expand environment variables in manifests)
and apply:

```bash
envsubst < gadgets/trace_gpu_starvation/demo/video-frame-inference.yaml | kubectl apply -f -
```

This starts three pods (`gpu-starvation-bad`, `gpu-starvation-good`,
`gpu-starvation-threaded`), each requesting one GPU and looping forever.
Run only the one you need by editing the manifest, or apply all three and
compare. Follow a pod's per-frame timing with:

```bash
kubectl logs -f gpu-starvation-bad
```

Clean up when finished:

```bash
kubectl delete -f gadgets/trace_gpu_starvation/demo/video-frame-inference.yaml
```

## Observe with the gadgets

With Inspektor Gadget deployed on the cluster (see
[ig-gpu-instructions](https://github.com/inspektor-gadget/ig-gpu-instructions)),
watch the starving thread and its stack:

```bash
# Tracer: one event per stall window
kubectl gadget run trace_gpu_starvation:latest \
    --collect-ustack --collect-otel-stack --symbolizers otel-ebpf-profiler

# Profiler: duration-weighted flamegraph to Pyroscope/Grafana
kubectl gadget run profile_cpu:latest --gpu-idle-only \
    --collect-ustack --collect-otel-stack --symbolizers otel-ebpf-profiler
```

Against `gpu-starvation-bad` the gadgets attribute the wasted CPU to the
`cv2.resize` / numpy preprocessing path; against `gpu-starvation-good`
they stay quiet because the GPU is kept busy. Python source lines from both
`trace_gpu_starvation` and `profile_cpu --gpu-idle-only` require
`--collect-otel-stack --symbolizers otel-ebpf-profiler` and the IG DaemonSet
running with `hostPID=true`; without those flags they still resolve native
(C/C++, numpy) frames from symbol tables.
