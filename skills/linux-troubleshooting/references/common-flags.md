# Common flags, scoping & gotchas (standalone `ig`)

All examples assume `sudo ig run <gadget>:latest …`. Confirm any flag with
`--help` (see `discovering-params-and-fields.md`) — this file lists the ones
you'll use most.

## Scope the trace (do this first)

| Goal | Flag | Example |
|---|---|---|
| One container | `-c <name>` | `-c nginx` (comma-list; `!name` excludes) |
| A container runtime | `--runtimes <r>` | `--runtimes containerd` (docker/cri-o/podman) |
| Host (non-container) processes | `--host` | include processes outside any container |
| Only a process name | `--comm <name>` | `--comm curl` |
| Only a pid | `--pid <n>` | `--pid 1234` |

Without `--host`, `ig` shows **container** events (enriched with
`runtime.containerName` and `runtime.runtimeName`). Add `--host` to also see bare-host
processes. Narrow scope = less noise, faster root-cause.

## Always bound the run

- **`--timeout <seconds>`** — for every streaming (`trace_*`) gadget; start 5-10s.
- **`--max-entries <n>`** — for `top_*`/`snapshot_*` to cap rows.
- Prefer several short, scoped runs over one long unscoped one.

## Output modes

| Mode | When |
|---|---|
| `-o json` | machine parsing with `jq`; the default for agents |
| `-o jsonpretty` | eyeballing nested structure |
| `-o columns --fields a,b,c` | compact human table of just the fields you need (the `-o columns=a,b,c` comma form is parsed as separate output modes and prints nothing) |
| default | gadget's built-in columns; quick look |

Streaming datasources produce newline-delimited JSON objects; map-backed
top/snapshot datasources produce JSON arrays. Match the `jq` expression to the
shape (see `discovering-params-and-fields.md`).

## Filter events with the native filter operator

- **`--filter <field><op><value>`** (short **`-F`**) filters rows before output.
  Operators include `==`, `!=`, `>=`, `<=`, `>`, `<`, `~` (regex match), and
  `!~` (regex non-match). Combine rules with commas, for example
  `--filter 'comm==curl,error!=0'`.
- **`--filter-expr <expr>`** (short **`-E`**) accepts the richer expression
  language. Confirm datasource-specific forms with the gadget's `--help`.
- The filter operator currently runs in user space, like `jq`, but it is the
  native interface and can move closer to eBPF without changing your command.

## `top_*` gadgets: rank and refresh

- **`--sort <field>`** orders rows; prefix a field with `-` for descending and
  join multiple fields with `,`.
- **`--map-fetch-interval <dur>`** controls how often map-backed results are
  fetched (default `1000ms`); raise it to reduce polling frequency.
- Combine sorting with **`--max-entries <n>`** to keep only the most useful rows.

## Common enrichment fields (standalone `ig`)

- `runtime.containerName`, `runtime.runtimeName`, `runtime.containerImageName` —
  the container identity of the event (when a runtime is present).
- `proc.comm`, `proc.pid`, `proc.tid`, `proc.creds.uid`/`.gid` — the process.
- `timestamp`; endpoints as `src`/`dst` with nested `.addr`, `.port`.
- Note: `k8s.*` fields are **empty for non-container / host processes**, but `ig`
  *does* support Kubernetes enrichment on a cluster node — pass
  **`--enrich-with-k8s-apiserver`** to connect to the API server and populate
  `k8s.namespace`/`k8s.podName`/`k8s.containerName`/…. Scope local Kubernetes
  events with the long-form `--k8s-namespace`, `--k8s-podname`,
  `--k8s-containername`, and `--k8s-selector` flags. Use `kubectl gadget` for
  cluster-wide tracing; for host-only tracing rely on the `runtime.*` fields.

## Gotchas

- **Tag defaults to `:latest`.** `sudo ig run <gadget>` without a tag resolves to
  `<gadget>:latest` automatically. Use an immutable version tag or digest for
  reproducibility; `:latest` is mutable.
- **`ig` needs privileges.** Run with `sudo` (or CAP_BPF/CAP_SYS_ADMIN). Loading
  eBPF fails without them.
- **BTF required.** The host kernel needs `/sys/kernel/btf/vmlinux` (CO-RE).
- **Path fields need `--paths`.** Fields like `cwd`/`exepath`/`fpath` are empty
  unless you pass `--paths`.
- **`--failed`/`--failure-only` narrows to errors** on many trace gadgets
  (`trace_open --failed`, `trace_tcp --failure-only`) — use it when hunting a
  failure; it cuts noise hard.
- **A locally-built image can shadow the upstream one.** To guarantee a fresh
  registry copy, use **`--pull always`**; use a pinned digest when exact
  reproducibility matters.
- **Bare field vs `*_raw`.** Numeric fields often render as a human-formatted
  string (`latency_ns`="1.2ms", `memoryRSS`="12 MB"); the `_raw` sibling
  (`latency_ns_raw`, `memoryRSS_raw`) is the machine number — use `_raw` for
  arithmetic/sort/`jq`, the bare field for display. Both appear under `--fields`.
- **Daemon mode.** For repeated runs you can start `sudo ig daemon` and connect a
  client, but one-shot `sudo ig run …` is fine for troubleshooting.
