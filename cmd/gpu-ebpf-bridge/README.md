# gpu-ebpf-bridge

`gpu-ebpf-bridge` is a userspace daemon that polls GPU telemetry via
NVML and publishes it through four bpffs-pinned BPF maps that consumer
eBPF gadgets read from.

The documentation lives under `docs/` so it is published on the
website:

- Command-line reference (flags, the four maps, `--dump`, backends):
  [`docs/reference/gpu-ebpf-bridge-cli.md`](../../docs/reference/gpu-ebpf-bridge-cli.md)
- Deployment guide (helm chart, `kubectl debug node`, local `ig`,
  ig-in-container, `ig daemon`):
  [`docs/reference/gpu-ebpf-bridge.md`](../../docs/reference/gpu-ebpf-bridge.md)
- Architecture and design rationale:
  [`docs/design/004-gpu-telemetry-enricher.md`](../../docs/design/004-gpu-telemetry-enricher.md)
