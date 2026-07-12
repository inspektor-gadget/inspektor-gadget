# Companion: switching to the standalone `ig` (single host)

This skill (`kubernetes-troubleshooting`) drives Inspektor Gadget **in a
Kubernetes cluster** via `kubectl gadget run`, enriching every event with
namespace / pod / container / node.

**Switch to the `linux-troubleshooting` skill (standalone `ig` binary) when the
target is not a cluster:**

- A **bare Linux host**, VM, edge node, or CI runner with no Kubernetes.
- A **single node's container runtime** directly (Docker / containerd / CRI-O /
  podman) — e.g. you're SSH'd into one node and want to trace only its local
  containers without going through the API server.
- **Host (non-container) processes** — `ig --host` sees processes outside any
  container, which the cluster path does not target.
- The cluster's IG DaemonSet isn't (and can't be) deployed, but you can `sudo`
  on the node.

The **gadgets, flags, fields, and the discover-don't-guess rule are identical** —
only the launcher and the enrichment metadata differ:

| | `kubernetes-troubleshooting` | `linux-troubleshooting` |
|---|---|---|
| Launcher | `kubectl gadget run <g>:latest` | `sudo ig run <g>:latest` |
| Scope flags | `-n` / `-p` / `-c` | `-c` / `--host` / `--runtimes` |
| Enrichment | `k8s.namespace/podName/…` | `runtime.containerName/runtimeName` |
| Needs | in-cluster IG DaemonSet | root on the host |

If you're already at a shell on a node, `ig` is often faster (no DaemonSet, no
API round-trip). If you need cluster-wide, pod-aware correlation, stay with
`kubectl gadget`.
