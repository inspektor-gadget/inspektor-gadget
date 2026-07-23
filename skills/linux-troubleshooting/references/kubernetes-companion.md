# Companion: switching to `kubectl gadget` (Kubernetes clusters)

This skill (`linux-troubleshooting`) drives Inspektor Gadget on a **single Linux
host** via the standalone `sudo ig run` binary, enriching events with container
name / runtime.

**Switch to the `kubernetes-troubleshooting` skill (`kubectl gadget run`) when
the target is a Kubernetes cluster:**

- The symptom is about a **pod / Service / Deployment**, not a bare process.
- You need **cluster-wide** tracing across many nodes from one command.
- You need events enriched with `k8s.namespace`, `k8s.podName`,
  `k8s.containerName`, and `k8s.node` so you can correlate a kernel event back
  to a workload.
- You want to trace **by namespace / pod / label** (`-n` / `-p` / selectors).

The **gadgets, flags, fields, and the discover-don't-guess rule are identical** —
only the launcher and enrichment differ:

| | `linux-troubleshooting` | `kubernetes-troubleshooting` |
|---|---|---|
| Launcher | `sudo ig run <g>:latest` | `kubectl gadget run <g>:latest` |
| Kubernetes scope flags | `--k8s-namespace`, `--k8s-podname`, `--k8s-containername`, `--k8s-selector` (long form only) | `-n`, `-p`, `-c`, `-l` |
| Enrichment | `runtime.*`; local `k8s.*` with Kubernetes API enrichment | `k8s.namespace`, `k8s.podName`, `k8s.containerName`, `k8s.node` |
| Needs | root on the host; local container runtime | in-cluster IG DaemonSet |

When you follow a `kubectl gadget run …` example from the shared domain playbooks
(e.g. the security or storage flow), translate Kubernetes short scope flags to
their long `--k8s-*` forms. Keep `k8s.*` fields when local Kubernetes enrichment
is available; otherwise use `runtime.containerName`. Add `--host` to include
non-container processes. Example — the "permission denied" capability check on a
host:

```bash
sudo ig run trace_capabilities:latest -c <container> --timeout 15 \
  -o columns --fields runtime.containerName,proc.comm,cap,capable,syscall
```

Rule of thumb: **one node → `ig`; cluster-wide tracing → `kubectl gadget`.**
Standalone `ig` can enrich local-runtime events with Kubernetes identity; use
`kubectl gadget` when one command must cover workloads across nodes.
