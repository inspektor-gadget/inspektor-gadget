---
title: gpu-ebpf-bridge
sidebar_position: 900
description: >
  Deploy the gpu-ebpf-bridge daemon alongside Inspektor Gadget to
  expose per-device and per-process GPU telemetry to consumer
  gadgets.
---

The `gpu-ebpf-bridge` daemon polls NVIDIA GPU telemetry via NVML and
publishes it through four bpffs-pinned BPF maps that consumer
gadgets read from. Gadgets can then enrich kernel-side events
(kprobes, uprobes, tracepoints) with per-process or per-device GPU
context in one hash lookup at event emit time.

See the design document [`004-gpu-telemetry-enricher`][design] for
the architecture and the command-line reference in
[`cmd/gpu-ebpf-bridge/README.md`][cli] for flags and internals.
This page focuses on deployment.

[design]: https://github.com/inspektor-gadget/inspektor-gadget/blob/main/docs/design/004-gpu-telemetry-enricher.md
[cli]: https://github.com/inspektor-gadget/inspektor-gadget/blob/main/cmd/gpu-ebpf-bridge/README.md

## Requirements

- NVIDIA GPU with driver **>= 545** (CUDA 12.3, October 2023) or newer.
- Kernel **>= 5.8** (for `BPF_MAP_TYPE_LRU_HASH` and
  `bpf_iter/bpf_map_elem`, used by the maps and by consumer gadgets).
- Access to `/sys/fs/bpf` inside the bridge container (bpffs must be
  mounted; the bridge is typically deployed alongside IG, which
  already mounts it).
- `libnvidia-ml.so.1` from the NVIDIA driver, available inside the
  bridge container at runtime. Bind-mounted from the host; the
  container image itself does not ship NVIDIA libraries. See the
  per-mode setup below.

## Kubernetes: helm chart (recommended)

Enable the bridge as a sidecar in the existing IG DaemonSet via a
single helm value:

```yaml
# values.yaml
bridges:
  gpu:
    enabled: true
hostPID: true
```

`hostPID: true` is required alongside `bridges.gpu.enabled: true`: NVML
enumerates GPU-using processes via `/proc` reads and returns host
PIDs from `nvmlDeviceGetComputeRunningProcesses`, so the bridge
sidecar must share the host PID namespace. The chart's template
refuses to render if `bridges.gpu.enabled` is `true` without `hostPID:
true`, so you'll get a clear error at `helm install` time rather
than an empty per-PID map at runtime. Same reason DCGM Exporter
sets `hostPID: true` in its own helm chart.

By default (`accessMode: toolkit-env`) the sidecar sets the two
NVIDIA Container Toolkit environment variables that trigger the
`runc` prestart hook to bind-mount libnvidia-ml.so.1 and grant
`/dev/nvidia*` access, without reserving a GPU for scheduling.

**The IG DaemonSet runs on every Linux node** whether GPUs are
present or not. On non-GPU nodes the bridge's `--idle-if-no-gpu`
flag catches the "NVML unavailable" error, logs a warning, and
sleeps until SIGTERM — the sidecar stays in `Running` state without
crashing or restarting. This preserves fleet-wide IG observability
on mixed clusters. If you'd rather restrict IG (and the bridge) to
GPU nodes only, set `.Values.nodeSelector` yourself; there is no
separate `gpu.nodeSelector`.

Three deployment modes are supported to match your cluster's setup:

### `toolkit-env` (default)

`toolkit-env` works on clusters where the NVIDIA Container Toolkit is
installed and `nvidia-container-runtime` is the default container
runtime:

- Vanilla Kubernetes with the [NVIDIA GPU Operator][gpu-operator]
- Google GKE with [cos_containerd GPU nodes][gke-gpu]
- Red Hat OpenShift with the [NVIDIA GPU Operator][openshift-gpu]
- AKS clusters with the NVIDIA GPU Operator installed on the default
  node pool
- AKS [managed GPU node pools][aks-managed-gpu] (preview; AKS
  auto-installs the NVIDIA driver, device plugin, and DCGM exporter)
  — confirmed working with toolkit-env

`toolkit-env` uses the same access pattern as NVIDIA's [DCGM
Exporter][dcgm]: the `utility` capability grants read-only NVML
telemetry (utilization, memory, per-process usage) but not CUDA
compute, and — unlike `device-plugin` mode — it does not reserve a
GPU, so all GPUs remain available to your workloads.

[dcgm]: https://github.com/NVIDIA/dcgm-exporter
[aks-managed-gpu]: https://learn.microsoft.com/en-us/azure/aks/aks-managed-gpu-nodes#managed-gpu-components
[gpu-operator]: https://docs.nvidia.com/datacenter/cloud-native/gpu-operator/latest/getting-started.html
[gke-gpu]: https://cloud.google.com/kubernetes-engine/docs/how-to/gpus
[openshift-gpu]: https://docs.nvidia.com/datacenter/cloud-native/openshift/latest/index.html

### `hostpath`

`hostpath` is a fallback for clusters where the `toolkit-env`
approach fails — e.g. some AKS GPU node pool configurations whose
nvidia-device-plugin denies `NVIDIA_VISIBLE_DEVICES` from
non-`nvidia.com/gpu`-requesting pods as a security precaution. (Note:
AKS *managed* GPU node pools have been observed to work with
`toolkit-env`; use `hostpath` only if you hit the device-plugin
denial or run a bring-your-own-driver pool.)

`hostpath` bind-mounts the host's `/dev` at `/host/dev` and `/usr` at
`/host/usr` (read-only). Both source paths exist on every Linux
node, so kubelet accepts the pod on non-GPU nodes too. At startup
the bridge globs `/host/dev/nvidia*` and creates symlinks in the
container's `/dev` so NVML and CUDA find the devices at the paths
they expect. The bridge also searches for `libnvidia-ml.so.1` under
`/host/usr/lib{,64,/x86_64-linux-gnu}/` and passes the absolute
path to NVML's dlopen, covering
Debian/Ubuntu/AKS/RHEL/Fedora/CentOS/OpenShift with one config
and without polluting `LD_LIBRARY_PATH` — dragging the host's libc
into the container's dynamic-linker search path would trigger
`*** stack smashing detected ***` on any glibc-version mismatch.

```yaml
bridges:
  gpu:
    enabled: true
    accessMode: hostpath
```

`hostpath` works on any cluster with an NVIDIA driver installed on
the host, regardless of the container runtime configuration or the
host's distro. On non-GPU nodes the bind mounts still succeed (source
paths exist), the symlink step finds no `nvidia*` entries, and
`--idle-if-no-gpu` handles the NVML failure.

### `device-plugin`

`device-plugin` is **not recommended** for fleet-wide telemetry. It
requests `nvidia.com/gpu: 1` in the sidecar's `resources.limits`,
which reserves a full GPU per node for the bridge. Only useful if you
have MIG partitioning with a dedicated telemetry partition:

```yaml
bridges:
  gpu:
    enabled: true
    accessMode: device-plugin
```

### `kubectl gadget deploy`

`kubectl gadget deploy` currently uses a pre-rendered manifest
(`pkg/resources/manifests/deploy.yaml`) generated from this helm
chart with default values (`bridges.gpu.enabled=false`), so it does **not**
deploy the bridge. Use `helm install ... --set bridges.gpu.enabled=true`
above instead.

Once [issue #5592][5592] (migrating `kubectl gadget deploy` to use
the helm chart directly) is resolved, `kubectl gadget deploy` will
support `bridges.gpu.enabled=true` transparently with no additional work.

[5592]: https://github.com/inspektor-gadget/inspektor-gadget/issues/5592

## Kubernetes: `kubectl debug node`

For one-shot ad-hoc use without a cluster-wide install, run the
bridge in one `kubectl debug node` invocation and the gadget in
another:

```bash
# Terminal 1: start the bridge on the target node.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest \
        -- gpu-ebpf-bridge --mode=real --keep-pins=true

# Terminal 2: run a GPU-consuming gadget on the same node.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/ig:latest \
        -- ig run <gadget-image>
```

Both `kubectl debug node` containers share `/sys/fs/bpf` under
`--profile=sysadmin`, so the maps published by the bridge are
visible to `ig` in the second container.

## Linux (no Kubernetes)

Run the bridge as a background process before starting a gadget:

```bash
sudo gpu-ebpf-bridge --mode=real --keep-pins=true &
sudo ig run <gadget-image>
```

`--keep-pins=true` leaves the four maps in bpffs after the bridge
exits, so a subsequent `ig run` still sees the (now stale) data;
drop the flag to have the maps disappear on bridge shutdown.

## `ig` in a container

Run the bridge and `ig` as sibling containers, both sharing
`/sys/fs/bpf`:

```bash
docker run -d --rm --name gpu-ebpf-bridge --privileged --gpus all \
        -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest

docker run -ti --rm --privileged --pid=host \
        -v /:/host -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/ig:latest run <gadget-image>
```

`--gpus all` triggers the NVIDIA Container Toolkit hook on the
bridge container only; the ig container does not need GPU access.

## Verifying the deployment

Once the bridge is running, check the maps are being populated:

```bash
# Inside a container that shares /sys/fs/bpf with the bridge:
sudo gpu-ebpf-bridge --dump
```

Expect one entry per active GPU under `gpu_device`, and per-PID
entries under `gpu_per_pid` and `gpu_per_pid_per_device` once a
CUDA workload starts.

## Non-GPU nodes

The bridge distinguishes two behaviours when NVML is unavailable
(no `libnvidia-ml.so.1`, no `/dev/nvidia*`, or driver error):

- **Default (standalone, `docker run`, systemd)**: bridge logs the
  error and exits with a non-zero status. This surfaces
  misconfiguration loudly for operators who expect a working GPU.
- **`--idle-if-no-gpu` (helm-chart default)**: bridge logs a warning
  and blocks until SIGTERM. The container stays in `Running` state
  (no `CrashLoopBackOff`), so the IG DaemonSet is unaffected on
  mixed clusters that have both GPU and non-GPU nodes.

The helm chart passes `--idle-if-no-gpu` unconditionally when
`bridges.gpu.enabled=true`, so no user action is needed to get the mixed-
cluster behaviour. If you'd rather restrict IG to GPU nodes only,
set `.Values.nodeSelector` yourself (e.g. `accelerator: nvidia` for
AKS default GPU pools, or `nvidia.com/gpu.present: "true"` when the
NVIDIA GPU Operator is installed).
