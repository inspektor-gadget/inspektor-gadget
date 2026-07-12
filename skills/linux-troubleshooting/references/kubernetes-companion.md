# Companion: switching to `kubectl gadget` (Kubernetes clusters)

This skill (`linux-troubleshooting`) drives Inspektor Gadget on a **single Linux
host** via the standalone `sudo ig run` binary, enriching events with container
name / runtime.

**Switch to the `kubernetes-troubleshooting` skill (`kubectl gadget run`) when
the target is a Kubernetes cluster:**

- The symptom is about a **pod / Service / Deployment**, not a bare process.
- You need **cluster-wide** tracing across many nodes from one command.
- You need events **enriched with `k8s.namespace` / `podName` / `containerName`
  / `node`** so you can correlate a kernel event back to a workload.
- You want to trace **by namespace / pod / label** (`-n` / `-p` / selectors).

The **gadgets, flags, fields, and the discover-don't-guess rule are identical** —
only the launcher and enrichment differ:

| | `linux-troubleshooting` | `kubernetes-troubleshooting` |
|---|---|---|
| Launcher | `sudo ig run <g>:latest` | `kubectl gadget run <g>:latest` |
| Scope flags | `-c` / `--host` / `--runtimes` | `-n` / `-p` / `-c` |
| Enrichment | `runtime.containerName/runtimeName` | `k8s.namespace/podName/…` |
| Needs | root on the host | in-cluster IG DaemonSet |

When you follow a `kubectl gadget run …` example from the shared domain playbooks
(e.g. the security or storage flow), translate it for a host: drop `-n`/`-p`, swap
the enrichment field `k8s.podName`/`k8s.containerName` → `runtime.containerName`,
and add `--host` to include non-container processes. Example — the "permission
denied" capability check on a host:

```bash
sudo ig run trace_capabilities:latest -c <container> --timeout 15 \
  -o columns=runtime.containerName,proc.comm,cap,capable,syscall
```

Rule of thumb: **one node, no cluster → `ig`; a Kubernetes workload → `kubectl
gadget`.** If you're SSH'd into a single node and only care about its local
containers, `ig` is faster (no DaemonSet, no API round-trip); if you need
pod-aware, cluster-wide correlation, use `kubectl gadget`.
