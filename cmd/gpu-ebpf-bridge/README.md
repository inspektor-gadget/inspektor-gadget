# gpu-ebpf-bridge

`gpu-ebpf-bridge` is a userspace daemon that polls GPU telemetry via
[NVML](https://docs.nvidia.com/deploy/nvml-api/) and publishes it
through four bpffs-pinned BPF maps. Consumer eBPF gadgets can then
join by PID or by device index at event emit time, in one hash
lookup, without any inter-process communication with the bridge.

For the full architecture and design rationale, see the design
document [`docs/design/004-gpu-telemetry-enricher.md`][design].

## Data plane: the four maps

The bridge pins these under `/sys/fs/bpf/` at startup:

| Map                       | Type       | Key                              | Value struct                       |
|---------------------------|------------|----------------------------------|------------------------------------|
| `gpu_meta`                | ARRAY[1]   | `u32` (0)                        | `struct gpu_meta`                  |
| `gpu_device`              | ARRAY[16]  | `u32` device idx                 | `struct gpu_device_metrics`        |
| `gpu_per_pid`             | LRU_HASH   | `u32` host PID                   | `struct gpu_pid_metrics_aggregated`|
| `gpu_per_pid_per_device`  | LRU_HASH   | `u64 = (pid << 32) \| dev_idx`   | `struct gpu_pid_metrics`           |

The schema lives at [`include/gadget/gpu_types.h`][schema] and is
loaded into the kernel's BTF as part of the bridge's BPF object, so
consumer gadgets can `BPF_CORE_READ` fields by name.

### Timestamps & freshness

The bridge mixes two clocks, because eBPF and NVML disagree on which
one they use:

- **eBPF programs** timestamp events with `bpf_ktime_get_boot_ns()` —
  i.e. `CLOCK_BOOTTIME`. This is the clock a consumer gadget has on hand
  when it does its map lookup.
- **NVML** timestamps its samples with `CLOCK_REALTIME` microseconds
  since the Unix epoch (verified empirically on an A100, driver
  580.126.09). The bridge preserves that wall-clock time in the
  per-sample `timestamp_ns` fields (e.g. `gpu_device.timestamp_ns`)
  rather than overwriting it with the poll time, so consumers can measure
  how long a device has been idle.

To bridge the two, `gpu_meta` carries:

- `last_update_boottime_ns` — `CLOCK_BOOTTIME` nanoseconds at the last
  successful poll. Consumers compare this against their own
  `bpf_ktime_get_boot_ns()` to reject stale telemetry.
- `clock_offset_ns` — signed `CLOCK_REALTIME − CLOCK_BOOTTIME` in
  nanoseconds, recomputed every poll (so NTP steps are picked up within
  one interval). Convert an NVML wall-clock field to the consumer's
  boot clock with: `boottime_ns = realtime_ns − clock_offset_ns`.

The bridge writes the per-PID maps first and bumps `gpu_meta` last, so a
consumer that gates on `last_update_boottime_ns` never observes a
half-updated snapshot.

## CLI

```
gpu-ebpf-bridge [flags]

Flags:
  --mode string           Backend selection: auto (default), real, mock.
                          auto tries real and falls back to mock on failure.
  --poll-interval duration
                          Time between NVML polls (default 100ms).
  --pin-dir string        Where to pin the four maps (default /sys/fs/bpf).
  --keep-pins             Leave maps pinned when the process exits (debug).
                          Default false; pins are cleaned up on SIGINT/SIGTERM.
  --log-level string      debug, info, warn, error (default info).
  --dump                  Open the pinned maps read-only, print their
                          contents, and exit. Does not start the poller.
  --host-path string      When set, tells the bridge that the host's
                          filesystem (or a subtree) is bind-mounted at
                          this path. Combine with --symlink-nvidia-devs
                          and/or an LD_LIBRARY_PATH pointing under this
                          path to reach the host's NVIDIA driver from
                          inside a container. Empty by default.
  --symlink-nvidia-devs   On startup, glob ${host-path}/dev/nvidia* and
                          create symlinks in the container's /dev to
                          each entry. No-op on hosts without an NVIDIA
                          driver. Requires --host-path.
  --idle-if-no-gpu        When NVML init fails with ErrNotAvailable,
                          log a warning and block until SIGTERM instead
                          of exiting with an error. Intended for helm-
                          chart deployments on mixed clusters where the
                          same DaemonSet runs on GPU and non-GPU nodes.
  --nvml-library-path string
                          Absolute path to libnvidia-ml.so.1 to dlopen,
                          bypassing the dynamic linker's default search.
                          If empty and --host-path is set, the bridge
                          searches ${host-path}/usr/lib{,64,/x86_64-
                          linux-gnu}/libnvidia-ml.so.1 in order. Avoid
                          LD_LIBRARY_PATH pointing at broad system
                          library dirs, which would drag in the host's
                          libc and trigger a "stack smashing detected"
                          abort on glibc-version mismatch.
  --version               Print version and exit.
```

## Backends

- **real** (`-tags nvml` builds only): polls NVML via
  [`github.com/NVIDIA/go-nvml`][go-nvml]. Requires
  `libnvidia-ml.so.1` at runtime (dlopen'd; the bridge binary itself
  has no link-time reference to it). Minimum NVIDIA driver version
  **545 / CUDA 12.3** (October 2023).
- **mock** (always compiled in): fabricates plausible sinusoidal
  telemetry. Runs anywhere; used for local development, CI, and by
  the bridge's `--mode=auto` fallback on hosts without an NVIDIA
  driver.

## Debugging with `--dump`

For hosts where `bpftool` is not installed (fresh Azure/AWS VMs,
stock IG container image), `--dump` provides a built-in pretty-print
of all four maps:

```sh
sudo gpu-ebpf-bridge --dump
# gpu_meta
#   {SchemaVersion:1 N_devices:1 LastUpdateBoottimeNs:... ClockOffsetNs:... HelperPid:12345 ...}
# gpu_device
#   [device 0] {TimestampNs:... SmUtilPct:71 MemUtilPct:53 ...}
# gpu_per_pid
#   [pid 100000] {... UsedGpuMemoryTotal:268435456 SmUtilPctMax:38 ...}
# gpu_per_pid_per_device
#   [pid 100001 dev 0] {... UsedGpuMemory:402653184 SmUtilPct:49 ...}
```

`--dump` opens each pinned map read-only via bpffs; it is safe to
run alongside a live bridge daemon and does not disturb consumer
gadgets.

## Building

```sh
# Host binary (requires CGO + libnvidia-ml headers on the build host):
make gpu-ebpf-bridge

# Container image (recommended for deployment):
make gpu-ebpf-bridge-container
```

## Deployment

See [`docs/reference/gpu-ebpf-bridge.md`][deploy] for detailed
deployment instructions across all IG installation modes: helm chart
DaemonSet, `kubectl debug node`, local `ig` binary, ig-in-container,
and `ig daemon`.

[design]: ../../docs/design/004-gpu-telemetry-enricher.md
[schema]: ../../include/gadget/gpu_types.h
[deploy]: ../../docs/reference/gpu-ebpf-bridge.md
[go-nvml]: https://github.com/NVIDIA/go-nvml
