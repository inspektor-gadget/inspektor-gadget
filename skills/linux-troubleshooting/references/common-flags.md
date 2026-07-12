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
`runtime.containerName`/`runtimeName`). Add `--host` to also see bare-host
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
| `-o columns=a,b,c` | compact human table of just the fields you need |
| default | gadget's built-in columns; quick look |

## Common enrichment fields (standalone `ig`)

- `runtime.containerName`, `runtime.runtimeName`, `runtime.containerImageName` —
  the container identity of the event (when a runtime is present).
- `proc.comm`, `proc.pid`, `proc.tid`, `proc.creds.uid`/`.gid` — the process.
- `timestamp`; endpoints as `src`/`dst` with nested `.addr`, `.port`.
- Note: there are **no `k8s.*` fields** here — that enrichment is the Kubernetes
  path's job (`kubectl gadget`). If you need pod/namespace correlation, use the
  `kubernetes-troubleshooting` skill instead.

## Gotchas

- **`:latest` is required.** `run <gadget>` without a tag fails with
  `invalid reference format`; always `run <gadget>:latest` (or a pinned digest).
- **`ig` needs privileges.** Run with `sudo` (or CAP_BPF/CAP_SYS_ADMIN). Loading
  eBPF fails without them.
- **BTF required.** The host kernel needs `/sys/kernel/btf/vmlinux` (CO-RE).
- **Path fields need `--paths`.** Fields like `cwd`/`exepath`/`fpath` are empty
  unless you pass `--paths`.
- **`--failed`/`--failure-only` narrows to errors** on many trace gadgets
  (`trace_open --failed`, `trace_tcp --failure-only`) — use it when hunting a
  failure; it cuts noise hard.
- **A locally-built image can shadow the upstream one** and fail signature
  verification. If you hit a cosign/signature error on `:latest`, pull the
  upstream image by digest (or use the documented verification override in a
  trusted context). Prefer the upstream image.
- **Bare field vs `*_raw`.** Numeric fields often render as a human-formatted
  string (`latency_ns`="1.2ms", `memoryRSS`="12 MB"); the `_raw` sibling
  (`latency_ns_raw`, `memoryRSS_raw`) is the machine number — use `_raw` for
  arithmetic/sort/`jq`, the bare field for display. Both appear under `--fields`.
- **Daemon mode.** For repeated runs you can start `sudo ig daemon` and connect a
  client, but one-shot `sudo ig run …` is fine for troubleshooting.
