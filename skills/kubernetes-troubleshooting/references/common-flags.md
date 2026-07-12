# Common flags, output modes, scoping & gotchas (kubectl gadget)

All examples assume `kubectl gadget run <gadget>:latest`. Confirm any flag with
`-h` (see `discovering-params-and-fields.md`) — this file lists the ones you'll
use most, all verified against a live cluster.

## Scope the trace (do this first — cluster-wide traces are noisy)

| Goal | Flag | Example |
|---|---|---|
| One namespace | `-n <ns>` | `-n prod` |
| All namespaces | `-A` | `-A` |
| One pod | `-p <pod>` | `-p api-7d9` |
| Container name | `-c <name>` | `-c nginx` (comma-list; `!` excludes) |
| Only a process name | `--comm <name>` | `--comm curl` |
| A selector/podset | (filter output by `k8s.*` fields) | `-o json | jq 'select(.k8s.namespace=="prod")'` |

Narrow scope = less noise, less context burned, faster root-cause. Start at the
namespace or pod, not `-A`, unless you're hunting something cluster-wide.

## Always bound the run

- **`--timeout <seconds>`** — for every streaming (`trace_*`) gadget. Without it
  the gadget streams until interrupted and can flood your context. Start at 5-10s.
- **`--max-entries <n>`** — for `top_*` and `snapshot_*` gadgets, to cap rows.
- Prefer several short, scoped runs over one long unscoped one.

## Output modes

| Mode | When |
|---|---|
| `-o json` | machine parsing with `jq`; the default for agents |
| `-o jsonpretty` | eyeballing nested structure |
| `-o columns=a,b,c` | compact human table of just the fields you need |
| default (no `-o`) | gadget's built-in columns; fine for a quick look |

## Common enrichment fields (present on most gadgets via kubectl gadget)

- `k8s.namespace`, `k8s.podName`, `k8s.containerName`, `k8s.node` — the
  Kubernetes identity of the event. This enrichment is the whole point of
  `kubectl gadget`: every kernel event is tied back to a workload.
- `proc.comm`, `proc.pid`, `proc.tid`, `proc.creds.uid`/`.gid` — the process.
- `timestamp` — event time.
- Endpoints appear as `src`/`dst` with nested `.addr`, `.port`, and their own
  `.k8s.*` when the peer is in-cluster.

## Gotchas (learned from live runs)

- **`:latest` is required.** `run <gadget>` without a tag fails with
  `invalid reference format`; always `run <gadget>:latest` (or a pinned digest).
- **Path fields need `--paths`.** Fields like `cwd`/`exepath`/`fpath` are only
  populated when you pass `--paths`; otherwise they're empty.
- **`--failed`/`--failure-only` narrows to errors.** Many trace gadgets have a
  flag to show only failing events (e.g. `trace_open --failed`,
  `trace_tcp --failure-only`) — use it when hunting a failure, it cuts noise hard.
- **A locally-built gadget image can shadow the upstream one** and fail signature
  verification. If you hit a cosign/signature error on `:latest`, you likely have
  a local build with that name; pull by upstream digest or (in a trusted
  troubleshooting context) use the documented verification override. Prefer the
  upstream image.
- **Version skew warning is usually benign.** "gadget built with vX, run with vY"
  is a warning, not a failure — the run still produces data; note it and proceed.
- **Bare field vs `*_raw`.** Numeric fields often render as a human-formatted
  string (`latency_ns`="1.2ms", `memoryRSS`="12 MB", `throttledTime`="4ms"); the
  `_raw` sibling (`latency_ns_raw`, `memoryRSS_raw`, `throttledTime_raw`) is the
  machine number — use `_raw` for arithmetic/sort/`jq` comparisons, the bare
  field for display. Both appear under `-h`/`--fields`.
- **In-cluster IG must be present.** `kubectl gadget run` needs the IG DaemonSet
  (or `kubectl gadget deploy`). If commands hang or error on connectivity, verify
  `kubectl get pods -n gadget`.
