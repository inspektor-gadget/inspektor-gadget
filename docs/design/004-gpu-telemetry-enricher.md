# GPU Telemetry Support in Inspektor Gadget

## Summary

This document proposes an architecture for exposing per-device and
per-process GPU telemetry to Inspektor Gadget gadgets, so kernel-side
events (kprobes, uprobes, tracepoints) can be enriched with GPU
context in-kernel via a single BPF map lookup at emit time.

Two proof-of-concept gadgets already demonstrate what the design
enables (see [References](#references) for source links):

- **`gpu_top`** — device-level, refreshes once a second like `top`.
  One row per active GPU showing utilization, memory,
  temperature, power, clocks, throttle reasons, PCIe and NVLink
  bandwidth, ECC counters, and more:

  ```
  DEVICE SM_UTIL_PCT MEM_UTIL_PCT     MEM_USED    MEM_TOTAL TEMP_C POWER_MW
       0          71           53        15 GB        80 GB     42   215000
  ```

- **`gpu_top_per_pid`** — per-process, refreshes once a second. One
  row per GPU-active PID, enriched via `gadget_process` so IG's
  standard container / pod / K8s enrichers attach the runtime
  context automatically:

  ```
  RUNTIME.CONTAINERNAME  COMM       PID    SM_UTIL  MEM_UTIL    MEM_USED  DEVICE  N
  training-job-7         python  12345         92        65       14 GB       0  1
  inference-server-2     python  12346         24        18        4 GB       0  1
  ```

Both use only two general-purpose IG-core mechanisms proposed in
[PR #5603][pr-5603] — bpffs-pin-by-name for gadget maps, and
non-destructive iteration of any BPF map via
`SEC("iter/bpf_map_elem")`. Both are consumers of a small, stable
data-plane contract (four bpffs-pinned eBPF maps with a versioned
schema); the remaining architectural question this document poses
is *who populates those maps*, for which three alternatives are
compared below.

## Motivation

There is a class of observability questions that today's tooling
answers poorly:

- When this CUDA kernel launched, was the GPU throttling thermally?
- When my Python training script was on-CPU, was the GPU idle
  (CPU-bound bottleneck)?
- Which pod just OOM-killed — and how much VRAM did it have allocated
  at the moment it died?
- Show me top processes by GPU memory, refreshed every second, with
  container / pod / namespace context.

Existing tools fragment along the wrong axes. `nvidia-smi` / DCGM
report device-level numbers but cannot correlate with per-event
kernel data. Vendor profilers (Nsight, CUPTI) give per-kernel detail
inside dedicated profiling sessions but cannot be joined with
kernel-side eBPF events without expensive out-of-band plumbing.

eBPF excels at the correlation layer: kprobes, uprobes, and
tracepoints run in-kernel and can join data via BPF maps in O(1)
hash lookups. The missing piece is a way to feed *GPU telemetry* into
a BPF map, since NVML has no in-kernel API. This proposal adds that
piece and defines a stable contract that gadgets can consume,
independent of how the data gets populated.

The "in-kernel join" property is the key value proposition. A
kernel-event gadget (e.g. `trace_cuda_launch`, `trace_oom_kill`,
`snapshot_process` extended with a GPU column) reads the current
GPU state from a shared map in one hash lookup and attaches it to
every event at emit time — no timestamp windowing, no post-hoc
correlation.

## Requirements

- **Feed GPU state into eBPF maps** with a stable schema, so gadget
  BPF programs can join by PID (or by device index) at event time.
- **Vendor-neutral naming.** Field names, map names, and struct
  layouts are `gpu_*`, not `nvml_*`, so a future AMD ROCm or Intel
  oneAPI provider publishing the same schema lets existing gadgets
  work unchanged.
- **Work correctly on non-GPU nodes.** IG typically runs as a
  DaemonSet on every node in a cluster. Nodes without GPUs must
  neither fail to start IG nor incur unavoidable GPU-library
  dependencies.
- **Optional at install time.** Users who don't need GPU telemetry
  should not have to think about it. Adding GPU support should be a
  targeted opt-in, not a global requirement.

## Data plane (invariant across all alternatives)

Regardless of which control-plane alternative is selected, the data
plane is the same. It is the contract that gadgets rely on.

Four maps are pinned in bpffs under `/sys/fs/bpf/`:

| Map | Type | Key | Value | Purpose |
|---|---|---|---|---|
| `gpu_meta` | ARRAY[1] | `u32` (0) | `struct gpu_meta` | Schema version, device count, last-update timestamp, helper PID |
| `gpu_device` | ARRAY[16] | `u32` device idx | `struct gpu_device_metrics` | Per-device telemetry: SM%, mem%, VRAM used/total, temp, power, clocks, throttle reasons, PCIe, NVLink, ECC |
| `gpu_per_pid` | LRU_HASH | `u32` host PID | `struct gpu_pid_metrics_aggregated` | Per-PID aggregated across devices: total VRAM, peak SM%, primary device |
| `gpu_per_pid_per_device` | LRU_HASH | `u64 = (pid << 32) \| dev` | `struct gpu_pid_metrics` | Detailed per-(PID, device) telemetry |

Full struct definitions are in the bridge's `include/gpu_types.h`,
which acts as the reference schema. If the bridge is packaged
in-tree (see alternative A below), the header would live at
`include/gadget/gpu_types.h` so consumer gadgets can include it via
the standard gadget include path. A `GPU_SCHEMA_VERSION` field in
`gpu_meta` lets consumers detect incompatible changes; forward-
compatible field additions rely on BPF CO-RE
(`bpf_core_field_exists`).

Consumer gadgets declare the maps they need with:

```c
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, struct gpu_pid_metrics_aggregated);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} gpu_per_pid SEC(".maps");
```

Two IG-core mechanisms make this work:

1. **`LIBBPF_PIN_BY_NAME` support in gadget maps** — allows a gadget
   to reuse an externally-pinned map by name instead of creating a
   fresh, empty one. Simple three-line change in
   `pkg/operators/ebpf/ebpf.go` (`Maps: ebpf.MapOptions{PinPath: "/sys/fs/bpf"}`).
2. **Non-destructive iteration** via `SEC("iter/bpf_map_elem")` +
   a new `GADGET_ITER_TARGET_MAP(prog, map)` macro that binds an
   iterator program to a specific map. This is required because the
   existing `GADGET_MAPITER` uses `BPF_MAP_LOOKUP_AND_DELETE_BATCH`
   and drains the target map — unacceptable when a separate writer
   is populating it.

Both are proposed in [inspektor-gadget/inspektor-gadget#5603][pr-5603].
They are general-purpose (not GPU-specific) and enable other
cross-process eBPF-map-sharing patterns beyond this proposal —
persistent-state gadgets, cross-gadget shared maps, and inspection
of externally-pinned maps.

[pr-5603]: https://github.com/inspektor-gadget/inspektor-gadget/pull/5603

For **per-event enrichment** (e.g. adding GPU columns to
`snapshot_process` or `top_process`), the gadget's BPF program does
a CO-RE-safe hash lookup at event emit time:

```c
__u32 z = 0;
struct gpu_meta *meta = bpf_map_lookup_elem(&gpu_meta, &z);
__u64 now = bpf_ktime_get_ns();
bool fresh = meta && bpf_core_field_exists(meta->last_update_ns)
                  && (now - meta->last_update_ns) < FRESHNESS_NS;
if (fresh) {
    struct gpu_pid_metrics_aggregated *p =
        bpf_map_lookup_elem(&gpu_per_pid, &pid);
    if (p && bpf_core_field_exists(p->sm_util_pct_max))
        event->gpu_sm = BPF_CORE_READ(p, sm_util_pct_max);
}
```

Cost when no writer is present: two hash lookups returning NULL
(~50-100 ns). Negligible; safe to include in every event-emitting
gadget.

## Control plane: three alternatives for populating the maps

### A. Separate writer process (current prototype)

A userspace daemon ([`gpu-ebpf-bridge`][gpu-ebpf-bridge]) polls NVML
at ~10 Hz on a worker goroutine and writes the four maps. Deployed
as a sidecar container in the same pod as IG (both containers share
`/sys/fs/bpf` via a bind mount).

**Packaging variants.** "Separate process" and "separate repository"
are orthogonal. The bridge could be packaged in three ways, from
least to most integrated with IG:

- **External repo, external image** (current prototype): the bridge
  lives at `github.com/alban/gpu-ebpf-bridge`, ships as its own
  container image, deployed as a sidecar in the IG pod. Maximum
  independence, weakest discoverability.
- **In-tree, separate image** (`cmd/gpu-ebpf-bridge` in the IG
  source tree, built into a distinct container image): the code is
  co-maintained with IG, versioned in lock-step, but the deployment
  is still a separate container in the pod. Better discoverability
  and IG maintainers own the review.
- **In-tree, same image, separate process** (built into the IG
  container image, launched as a sibling process): no extra
  container to deploy, sidecar UX collapses to zero. Retains
  process-level isolation from IG's main event loop. Requires a
  supervisor (tini, s6-overlay, or similar) inside the image.

All three are "alternative A" from an architectural standpoint (a
separate process writes the maps); they differ only in how the
bridge is distributed and deployed. The choice can be made
independently of the alternative-A vs B vs C question.

[gpu-ebpf-bridge]: https://github.com/alban/gpu-ebpf-bridge

**Pros:**

- **IG unchanged.** No new build-time dependencies, no libc/libdl
  linkage introduced, existing static build preserved.
- **Vendor-neutral by construction.** AMD ROCm or Intel oneAPI ships
  its own writer binary; IG remains vendor-agnostic. Multiple
  vendors could coexist on the same node.
- **Isolation.** An NVML segfault or driver quirk cannot take down
  IG or affect non-GPU gadgets. NVML's process-lifetime state and
  signal-handler quirks stay in a separate address space.
- **Independent release cycle.** The writer can iterate on NVML API
  coverage without waiting for IG releases.
- **Zero cost on non-GPU nodes.** The writer is not scheduled there;
  IG carries no GPU-library-related overhead.

**Cons:**

- **Deployment friction.** Users need to deploy a second container
  as part of the IG pod (or as a separate DaemonSet), which their
  organisations must evaluate for security.
- **Discoverability.** New IG users won't know they need to install
  the writer to unlock GPU columns.
- **Two-image distribution.** Vendor variants are separate container
  images rather than composable OCI artifacts.

### B. In-process Go enricher

A Go package inside the `ig` binary owns the same maps and runs the
NVML polling loop from within IG, analogous to how the existing
socket enricher (`pkg/socketenricher/`) maintains the `sockets` map.

**Pros:**

- **Zero deployment overhead.** IG works out of the box; users don't
  need to install anything extra.
- **Matches an established IG pattern** (the socket enricher). No
  new architectural concept to introduce.
- **Discoverability.** GPU columns Just Appear on GPU nodes.

**Cons:**

- **Vendor code enters IG core.** Multi-vendor support means either
  compile-time flags per vendor, or one vendor becoming the "blessed"
  one. Both increase IG's ongoing maintenance burden.
- **Reduced isolation.** An NVML bug can crash the IG process,
  including non-GPU gadgets.
- **Non-GPU nodes pay a small cost.** NVML symbols are resolved at
  IG startup on every node; dlopen failure is fast but non-zero.
- **NVML API-coverage churn is now IG's problem.** Every new NVML
  function or field triggers an IG release cycle.

**Note on map sharing.** With an in-process enricher, bpffs pinning
is no longer needed as the sharing mechanism. IG can pass the
enricher's maps into each gadget's collection at load time via
cilium/ebpf's `CollectionOptions.MapReplacements`, which supersedes
whatever the gadget's spec says about creation or pinning. Gadgets
written for option A (with `LIBBPF_PIN_BY_NAME`) still work in this
world — the replacement wins and the pinning directive becomes a
no-op — so the same gadget binary runs against either control-plane
option unchanged. Gadgets written specifically for a pure-in-process
world can drop the pinning directive for clarity.

**go-nvml vs purego (for this option only)**

Both bindings resolve `libnvidia-ml.so.1` via `dlopen()` at runtime
and do not require the library at build time. However, they differ
in their impact on IG's build:

- `github.com/NVIDIA/go-nvml` — cgo. Forces `CGO_ENABLED=1`, links
  libc dynamically, requires a C toolchain at build. Official
  Nvidia-maintained binding.
- `github.com/ebitengine/purego` — no cgo, but emits
  `//go:cgo_import_dynamic` directives for `dlopen`/`dlsym`, which
  cause the linker to add a `DT_NEEDED` entry for `libdl.so.2`. The
  resulting binary is still dynamically linked (verified: `ldd`
  shows `libdl.so.2`, `libc.so.6`, `libpthread.so.0`,
  `ld-linux-x86-64.so.2` even with
  `CGO_ENABLED=0 -extldflags '-static'`). No C toolchain at build.
  Requires hand-writing NVML bindings (~30 functions).

Full static linking is fundamentally incompatible with loading any
shared library at runtime — NVIDIA does not ship a static
`libnvidia-ml.a`, and reimplementing `ld-linux` inside purego is not
what purego does. This is the single constraint that rules option B
in or out. If the IG maintainers accept dropping the fully-static
build (for any reason — the announced wazero → wasmtime migration is
one such reason, but not the only possible one), option B becomes
viable and the go-nvml-vs-purego choice reduces to a matter of
maintenance preference: a cgo dependency elsewhere in IG (go-nvml)
vs hand-maintained bindings for ~30 NVML functions (purego).

### C. WASM operator packaged in an OCI image

Ship the enricher as a WASM module distributed as a separately-
pulled OCI artifact, loaded by IG's WASM operator subsystem
(`pkg/operators/wasm/`).

**Pros in principle:**

- OCI-distributed lifecycle: enricher updates without recompiling
  IG.
- Per-vendor enrichers ship as separate WASM images, pulled only on
  nodes that need them.
- Sandboxed guest code (memory-safe; guest cannot corrupt IG).

**Why this alternative is not viable as described:**

- **WASI has no `ioctl`.** NVML talks to `/dev/nvidiactl` via a
  large set of NVIDIA-proprietary ioctl codes (undocumented,
  version-specific). WASI (both preview1 and preview2) exposes file
  I/O — `fd_read`, `fd_write`, `path_open` — but nothing that would
  let a WASM guest make an ioctl. There is no path from a WASM
  module to the NVIDIA driver via WASI.
- **`libnvidia-ml.so.1` is a proprietary Linux ELF.** NVIDIA does
  not release its source, so it cannot be recompiled to WASM.
  Reimplementing it from scratch would require reverse-engineering
  the driver ioctl interface (unstable, driver-version-specific,
  undocumented). Impractical.
- **NVML is version-locked to the kernel driver.** `libnvidia-ml.so.1`
  and the loaded NVIDIA kernel module speak a versioned ioctl
  protocol; any mismatch is a hard failure (see "Deployment
  mechanics" below). Even if the two blockers above were resolved,
  bundling the library inside a WASM artifact would tie each artifact
  to a specific driver version and force one artifact per version to
  be distributed and matched at pull time. The pragmatic escape —
  bind-mount the host's `libnvidia-ml.so.1` — contradicts the
  "libraries included in the WASM module" premise.

**Workable variant.** IG could expose narrow custom host functions
(e.g. `ig_gpu_get_device_metrics(idx)`) and the WASM guest orchestrates
polling by calling them. But then `libnvidia-ml.so.1` is loaded by
IG itself, which reduces to option B plus a WASM runtime and a
host-function ABI. The sandbox provides no isolation for the NVML
surface, only for the (small, uninteresting) polling loop.

## Comparison at a glance

| Dimension | A: Bridge process | B: In-process enricher | C: WASM operator |
|---|---|---|---|
| Deployment complexity | Extra container per pod | Zero | Zero (once WASM enricher subsystem exists) |
| Extra container to security-review | Yes | No | No |
| Vendor code in IG core | None | Yes (per-vendor build tag or blessed vendor) | Same as B (WASM guest calls IG host functions that link NVML) |
| Multi-vendor coexistence | Trivial (parallel writer binaries) | Requires per-vendor code in IG | Trivial (parallel WASM artifacts, but IG hosts all vendor libs) |
| IG static build | Preserved | Lost (bridge already ends fully-static with wasmtime move) | Lost (same as B) |
| NVML crash blast radius | Bridge process only | IG process | IG process (WASM sandbox does not isolate host functions) |
| Cost on non-GPU nodes | 0 (not scheduled) | ~small (dlopen probe + failed symbol resolution) | Same as B |
| Match with existing IG pattern | New pattern (sidecar writer) | Yes (socket enricher) | New pattern (WASM as enricher, not gadget) |
| Discoverability | Requires docs / install step | Automatic | Automatic (once subsystem exists) |
| NVML API-coverage cadence | Bridge release | IG release | WASM artifact release (but host-function ABI is IG-release-tied) |
| Engineering cost from here | ~0 (already implemented) | Medium (rewrite poll loop as IG package + refactor for graceful degradation) | Large (add "enricher" as a WASM-operator category + host-function ABI + docs) |

## Deployment mechanics common to all options

Regardless of who loads NVML (bridge, IG, or an IG-hosted WASM
guest), the process holding it needs the same three things:

**1. Library provisioning.**
`libnvidia-ml.so.1` must match the exact version of the loaded
kernel driver — the two speak a versioned ioctl protocol and any
mismatch is a hard failure at `nvmlInit()`. Bundling in the
container image is therefore fragile (one image per driver version)
and universally avoided in practice. The library is bind-mounted
from the host at container start.

**1a. Library version vs NVML API surface.**
Separately from the driver-ioctl matching above, the *set of NVML
functions* that a given `libnvidia-ml.so.1` exposes grows over time
as NVIDIA adds new API in each CUDA release
(`nvmlDeviceGetProcessUtilization` in CUDA 8.0,
`nvmlDeviceGetMemoryInfo_v2` in driver 470, etc.). Consumers of NVML
have three strategies:

- **Versioned symbols (`_v2`, `_v3` suffixes)**: `go-nvml` probes for
  the newer symbol via `dlsym`, upgrades the function pointer if
  present, and falls back to the older signature otherwise. This
  handles the common case gracefully. The bridge relies on this for
  `nvmlInit_v2`, `nvmlDeviceGetPciInfo_v3`, `nvmlDeviceGetMemoryInfo_v2`,
  and similar.
- **Runtime feature probes**: for functions that are entirely absent
  in older libraries, the consumer needs to call `dl.Lookup("<sym>")`
  before invoking them and gate on the result. The bridge does not
  currently do this — direct cgo calls to functions not present in
  the loaded library will trigger `symbol lookup error` at runtime,
  the same failure mode as calling `nvmlShutdown()` after a failed
  init (see graceful-degradation section below).
- **Hardware-not-supported returns**: for cases where the function
  exists in the library but the specific GPU does not support the
  feature (older cards lacking NVLink, non-datacentre cards lacking
  fan control, etc.), the library returns `NVML_ERROR_NOT_SUPPORTED`.
  The bridge wraps every NVML call in a `safe()` helper that treats
  this (and a small set of related soft errors) as "field is zero,
  keep going", so the map field is reported as zero rather than
  causing a bridge error.

In practice, the bridge targets modern NVIDIA drivers. The most
recent NVML function it calls is
`nvmlDeviceGetCurrentClocksEventReasons`, which was added in driver
545 / CUDA 12.3 (October 2023) — so **driver 545 or newer** is the
current minimum. Older drivers can be supported by dropping the
`GetCurrentClocksEventReasons` upgrade and using only its
predecessor `GetCurrentClocksThrottleReasons` (present since driver
340 / 2013), which would lower the minimum to driver 470 / CUDA
11.4 (August 2021) — bounded then by `nvmlDeviceGetMemoryInfo_v2`.
Deploying on hosts with substantially older drivers is unsupported.
This should be documented as a minimum-driver-version requirement
rather than solved with per-function `dlsym` probes, which are
onerous and rarely justified given how recent the required feature
set is. The same policy applies identically to any of the three
alternatives (bridge, in-process enricher, or WASM-hosted): NVML
consumers all face the same compatibility choices.

**2. NVIDIA Container Toolkit — the industry-standard mechanism.**
On GPU-enabled nodes, `nvidia-container-toolkit` is installed on the
host and containerd/CRI-O uses `nvidia` as the default runtime (or a
runtime class). Its `runc` prestart hook automatically bind-mounts
`libnvidia-ml.so.1`, `libcuda.so.1`, etc. from the host into the
container's library search path and grants access to
`/dev/nvidiactl`, `/dev/nvidia0..N`, and `/dev/nvidia-uvm` via
cgroup device rules. Containers opt in via two environment
variables:

```yaml
env:
  - name: NVIDIA_VISIBLE_DEVICES
    value: "all"
  - name: NVIDIA_DRIVER_CAPABILITIES
    value: "utility"   # NVML + nvidia-smi. Does NOT include `compute`,
                       # so no GPU is reserved for scheduling. DCGM
                       # Exporter uses the same setting.
```

For the IG DaemonSet these two env vars are the whole delta.
Notably not needed:

- `resources.limits.nvidia.com/gpu` — this would reserve GPUs away
  from workloads; wrong for a telemetry consumer.
- Additional `SecurityContext` capabilities — IG is already
  privileged.
- RBAC changes — RBAC governs Kubernetes API access, not host device
  access.

**3. Fallback via HostPath mounts** (uncommon on production GPU
clusters, occasionally in dev environments): mount the character
devices under `/dev/nvidia*` and `libnvidia-ml.so.1` from the host's
`/usr/lib/x86_64-linux-gnu` (Debian/Ubuntu) or `/usr/lib64`
(RHEL/Fedora). Fragile because paths differ per distribution.

**4. Graceful degradation on GPU-less nodes.** IG runs on every
node; many will not have GPUs. On such nodes the toolkit hook does
nothing, `/dev/nvidiactl` is absent, and `libnvidia-ml.so.1` is not
in the container's library path. The enricher must detect this at
startup and disable the GPU code path. The natural probe is
`dlopen("libnvidia-ml.so.1")` returning NULL.

Implementations should also **not call any NVML function after a
failed `nvmlInit()`.** go-nvml is built with
`#cgo linux LDFLAGS: -Wl,--unresolved-symbols=ignore-in-object-files`
so the binary links successfully even when `libnvidia-ml.so.1` is
absent, but the direct `C.nvmlShutdown()` reference is still there —
calling it without a successful init triggers
`symbol lookup error: undefined symbol: nvmlShutdown` at runtime.
Purego avoids the problem entirely: it resolves every NVML symbol
via `dlsym` at runtime and never emits direct references, so a
missing library is caught at the `Dlopen()` boundary. Either way,
tracking an `initialized` bool that gates cleanup is the belt-and-
braces pattern the bridge already uses.

## Deployment across IG usage patterns

Where the bridge process runs depends on how the user has deployed
Inspektor Gadget. The four-map contract is deployment-agnostic —
gadgets look for maps at `/sys/fs/bpf/gpu_*` regardless — but the
operational shape of "how the bridge starts" differs across IG's
supported install modes (see
[quick-start](../quick-start.md)). None of the modes has a blocker.

**Kubernetes + helm chart (long-running DaemonSet).** The bridge
runs as an additional container in IG's existing DaemonSet, opt-in
via a helm value:

```yaml
# values.yaml (excerpt)
gpu:
  enabled: true       # add gpu-ebpf-bridge sidecar to the DaemonSet
```

The IG chart already knows how to share `/sys/fs/bpf` across
containers in the pod; adding one more container that mounts the
same path is a small chart change. Non-GPU nodes can be excluded via
a nodeSelector on `nvidia.com/gpu.present` (or similar label added
by the NVIDIA GPU Operator).

**Kubernetes + `kubectl debug node` (one-shot).** The user runs the
bridge with a first `kubectl debug node`, then runs the gadget with
a second:

```bash
# Terminal 1: start the bridge on the target node.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest \
        -- gpu-ebpf-bridge --mode=real --keep-pins=true

# Terminal 2: run any GPU-consuming gadget.
kubectl debug --profile=sysadmin node/mynode -ti \
        --image=ghcr.io/inspektor-gadget/ig:%IG_TAG% \
        -- ig run gpu_top:%IG_TAG%
```

Both containers see the same `/sys/fs/bpf` under `--profile=sysadmin`.

**Linux + local `ig` binary.** Run the bridge in the background
before running the gadget:

```bash
sudo gpu-ebpf-bridge --mode=real --keep-pins=true &
sudo ig run gpu_top:%IG_TAG%
```

`--keep-pins=true` leaves the four maps in bpffs after the bridge
exits, so a subsequent gadget invocation still sees the (now stale)
data; drop the flag to have the maps disappear on bridge shutdown.

**Linux + `ig` in a container.** Run the bridge as a separate
container that shares `/sys/fs/bpf` with the `ig` container:

```bash
docker run -d --rm --name gpu-ebpf-bridge --privileged --gpus all \
        -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/gpu-ebpf-bridge:latest

docker run -ti --rm --privileged --pid=host \
        -v /:/host -v /sys/fs/bpf:/sys/fs/bpf \
        ghcr.io/inspektor-gadget/ig:%IG_TAG% run gpu_top:%IG_TAG%
```

`--gpus all` triggers the NVIDIA Container Toolkit hook for the
bridge container only; the `ig` container needs no GPU access.

**`ig daemon` (client-server, MacOS/Windows clients).** Same as the
local-`ig` case: run the bridge on the Linux host alongside
`ig daemon`. No client-side configuration; the gadget runs on the
daemon's host and the bridge is a host-local dependency.

## Non-goals and use cases that don't fit

The bridge model — periodic poll of NVML, publish a snapshot to
bpffs-pinned maps — is a good fit for state-like telemetry that
consumers want to join with kernel events at emit time. Some NVML
capabilities do not fit this model well and are explicitly out of
scope for the four-map contract:

- **Event streams.** NVML's `nvmlEventSet` / `nvmlEventSetWait_v2`
  API emits edge-triggered notifications (XID errors, uncorrectable
  ECC events, single-bit ECC events, critical throttling
  transitions, GPU hot-plug). A snapshot map cannot capture these
  without loss between polls. The natural fit is a separate bridge
  output surface, most likely a userspace IPC channel (Unix socket
  or similar) rather than an extension of the bpffs map contract —
  BPF ring-buffer types have producer/consumer directions that
  don't fit "userspace writes async events, multiple gadgets read".
  Out of scope for v1; worth designing in a follow-up.
- **High-frequency sampled telemetry.** `nvmlDeviceGetSamples`
  returns burst-sampled time-series data at millisecond
  granularity. The bridge's ~100 ms poll interval is the
  ceiling; sub-tick detail is lost. Reducing the poll interval
  further risks unnecessary CPU cost across the fleet. Consumers
  needing this should use DCGM directly (`dcgm-exporter`).
- **Short-lived process detection.** A CUDA process that starts
  and exits between two polls is invisible to the bridge. NVML has
  no push notification for compute-process life-cycle. Catching
  every CUDA context creation requires uprobes on `cuCtxCreate` /
  `cuCtxDestroy` in `libcuda.so`, which is a separate gadget-side
  concern.
- **DCGM Profiling-style hardware performance counters.** Fields
  like `DCGM_FI_PROF_SM_OCCUPANCY`, `DCGM_FI_PROF_PIPE_TENSOR_ACTIVE`,
  `DCGM_FI_PROF_DRAM_ACTIVE` require multiplexing across a finite
  set of hardware counters at specific sampling windows. This is
  what DCGM's `nv-hostengine` is for; the bridge does not attempt
  to replicate it.
- **Non-flat structured data.** NVLink topology (per-device array
  of remote endpoints) and per-location ECC error breakdowns fit
  awkwardly into a flat map schema. The topology is essentially
  static, so a one-shot dump on the bridge's CLI is a better fit
  than a periodically-refreshed map.
- **Non-NVML sources.** CUPTI kernel-launch tracing, NVBit
  PTX-level instrumentation, and NVIDIA driver internal
  tracepoints are entirely outside NVML. Gadgets that need them
  attach directly (uprobes on `libcuda.so`, or dedicated tooling).

These are limitations of the state-snapshot model, not of the eBPF
integration itself. Some of them (notably event streams) are
natural v2 extensions to the bridge; others are outside NVML's
capability set entirely.

## Recommendation

**Ship option A (bridge process) as v1**, specifically the "in-tree,
separate image" packaging variant: the bridge source lives in the
Inspektor Gadget monorepo at `cmd/gpu-ebpf-bridge/`, its shared
header at `include/gadget/gpu_types.h`, and CI publishes it as a
distinct container image (`ghcr.io/inspektor-gadget/gpu-ebpf-bridge`)
alongside the existing `ig` and gadget images. This variant is
recommended because:

- The bridge exists, has been validated end-to-end on real hardware
  (NVIDIA A100 on Linux 6.17), and requires no changes to IG's build
  model.
- It is upstream-friendly: the only IG-core dependencies are the two
  general-purpose mechanisms (`LIBBPF_PIN_BY_NAME` support and
  `GADGET_ITER_TARGET_MAP`) from PR #5603, which are useful well
  beyond GPU telemetry.
- Co-maintenance in the IG tree gives maintainers full review over
  the bridge, keeps the schema header discoverable to gadget authors
  via the standard include path, and lets the bridge's release
  cadence follow IG's.
- A separate container image (rather than baking the NVML-linked
  binary into `ig` itself) keeps IG's own image free of libnvidia-ml
  dependencies and lets non-GPU deployments avoid pulling the bridge
  entirely — the helm chart opts users in via `gpu.enabled: true`
  (see the Deployment section above).

**Consider option B (in-process enricher) once the maintainers accept
dropping the fully-static build.** Whether that decision arrives on
its own (from the wazero → wasmtime migration, from a different
dependency, or from a deliberate choice) is orthogonal to the GPU
work; what matters is that once the constraint is gone, migrating
the poll loop into IG is a mechanical rewrite. The gadget-side code
essentially does not change: gadgets written for option A (using
`LIBBPF_PIN_BY_NAME`) continue to work under option B because
cilium/ebpf's `MapReplacements` overrides the pinning directive at
load time. A pure-B-world gadget can additionally drop the pinning
directive for clarity. Options A and B can coexist: IG's enricher
could detect a running bridge on startup and defer to it, or vice
versa.

**Do not pursue option C.** The WASM approach as described is
blocked by fundamental WASI / NVML-licensing constraints, and its
workable variant collapses into option B with additional WASM
infrastructure. If IG grows a general third-party-enricher story in
the future (WASM or otherwise), the four-map contract carries over
unchanged and any such enricher can populate it.

## Open questions

1. **Is dropping the fully-static IG binary acceptable?** This is
   the single decision that gates option B. It is a general IG
   question, not a GPU question — the answer applies to any future
   feature that depends on a runtime-loaded library. If the answer
   is yes, option B is on the table; if no, option A is the only
   path.
2. **Deployment friction as a hard constraint.** How strong is the
   "extra container = deal-breaker" signal from IG users? A weak
   signal means option A is acceptable indefinitely; a strong signal
   raises the priority of option B (contingent on question 1) —
   or of the "in-tree, same image, separate process" packaging
   variant of option A.
3. **Helm chart integration.** Regardless of packaging variant,
   the IG helm chart will need first-class support for the bridge
   so users don't have to hand-craft pod spec changes. What is the
   expected UX — a values.yaml toggle (`gpu.enabled: true`)? An
   auto-detected node selector? This should be scoped alongside the
   packaging decision.
4. **Third-party enrichers.** Is a general subsystem for user-
   contributed enrichers on the IG roadmap? If yes, the GPU work
   should be a first-class citizen of that subsystem rather than
   evolving in isolation.
5. **Vendor coverage priority.** AMD ROCm and Intel oneAPI parity —
   day-one, follow-up, or explicitly out of scope for now?

## References

- Prerequisite IG-core PR (LIBBPF_PIN_BY_NAME + iter/bpf_map_elem):
  [inspektor-gadget/inspektor-gadget#5603](https://github.com/inspektor-gadget/inspektor-gadget/pull/5603)
- Prototype writer: [alban/gpu-ebpf-bridge](https://github.com/alban/gpu-ebpf-bridge)
- POC consumer gadgets (`gpu_top`, `gpu_top_per_pid`) — pinned at
  commit
  [`56aedaa1`](https://github.com/inspektor-gadget/inspektor-gadget/tree/56aedaa19a6c9e5b65e52de2641953e4ed7d137c/gadgets):
  [`gpu_top`](https://github.com/inspektor-gadget/inspektor-gadget/tree/56aedaa19a6c9e5b65e52de2641953e4ed7d137c/gadgets/gpu_top),
  [`gpu_top_per_pid`](https://github.com/inspektor-gadget/inspektor-gadget/tree/56aedaa19a6c9e5b65e52de2641953e4ed7d137c/gadgets/gpu_top_per_pid).
  Both are stacked on top of PR #5603.
- Schema reference:
  [`include/gpu_types.h`](https://github.com/alban/gpu-ebpf-bridge/blob/c0dfda8b8e848d4148321f82c0796e7caad2bf86/include/gpu_types.h)
  in the writer repository.
