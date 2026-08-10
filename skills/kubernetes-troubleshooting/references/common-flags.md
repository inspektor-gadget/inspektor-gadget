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
| Label selector | `-l <sel>` / `--selector` | `-l app=api` (k8s label selector, comma-list; `!` excludes) |

Narrow scope = less noise, less context burned, faster root-cause. Start at the
namespace or pod, not `-A`, unless you're hunting something cluster-wide.

## Always bound the run

- **`--timeout <seconds>`** — for every streaming (`trace_*`) gadget. Without it
  the gadget streams until interrupted and can flood your context. Start at 5-10s.
- **`--max-entries <n>`** — for `top_*` and `snapshot_*` gadgets, to cap rows.
- Prefer several short, scoped runs over one long unscoped one.

## Filter events with the native filter operator

- **`--filter <field><op><value>`** (short **`-F`**) filters rows before output.
  Operators: `==`, `!=`, `>=`, `<=`, `>`, `<`, `~` (regex
  match), `!~` (regex non-match). Combine with commas: `--filter 'comm==curl,error!=0'`.
  Quote the expression (single quotes) especially with regex.
- **`--filter-expr <expr>`** (short **`-E`**) is the richer expression-language
  form for compound logic. Prefer `--filter` for simple field comparisons.
- The filter operator currently runs in user space, like `jq`, but it is the
  native interface and can move closer to eBPF without changing your command.
  Use it when you already know the field/value you want.

## `top_*` gadgets: rank and refresh

- **`--sort <field>`** orders rows; prefix a field with `-` for descending, join
  multiple with `,` (e.g. `--sort -rbytes,wbytes`). This is how you get "the
  heaviest N" — combine with `--max-entries <n>`.
- **`--map-fetch-interval <dur>`** sets how often the gadget snapshots its BPF
  maps (default `1000ms`); raise it (e.g. `5s`) to sample less often and reduce
  overhead on a busy host.

## Output modes

| Mode | When |
|---|---|
| `-o json` | machine parsing with `jq`; the default for agents |
| `-o jsonpretty` | eyeballing nested structure |
| `-o columns --fields a,b,c` | compact human table of just the fields you need (the `-o columns=a,b,c` comma form is parsed as separate output modes and prints nothing) |
| default (no `-o`) | gadget's built-in columns; fine for a quick look |

Streaming datasources produce newline-delimited JSON objects; map-backed
top/snapshot datasources produce JSON arrays. Match the `jq` expression to the
shape (see `discovering-params-and-fields.md`).

## Common enrichment fields (present on most gadgets via kubectl gadget)

- `k8s.namespace`, `k8s.podName`, `k8s.containerName`, `k8s.node` — the
  Kubernetes identity of the event. This enrichment is the whole point of
  `kubectl gadget`: every kernel event is tied back to a workload.
- `proc.comm`, `proc.pid`, `proc.tid`, `proc.creds.uid`/`.gid` — the process.
- `timestamp` — event time.
- Endpoints appear as `src`/`dst` with nested `.addr`, `.port`, and their own
  `.k8s.*` when the peer is in-cluster.

## Gotchas (learned from live runs)

- **Tag defaults to `:latest`.** `run <gadget>` without a tag resolves to
  `<gadget>:latest` automatically, so both forms work. Use an immutable version
  tag or digest for reproducibility; `:latest` is mutable.
- **Path fields need `--paths`.** Fields like `cwd`/`exepath`/`fpath` are only
  populated when you pass `--paths`; otherwise they're empty.
- **`--failed`/`--failure-only` narrows to errors.** Many trace gadgets have a
  flag to show only failing events (e.g. `trace_open --failed`,
  `trace_tcp --failure-only`) — use it when hunting a failure, it cuts noise hard.
- **A locally-built gadget image can shadow the upstream one.** To guarantee a
  fresh registry copy, use **`--pull always`**; use a pinned digest when exact
  reproducibility matters.
- **Treat version skew as a diagnostic signal.** The warning is not itself a
  failure, but field or protocol skew can change output or produce no useful
  rows. Prefer matching client, DaemonSet, and gadget versions before concluding
  that an empty trace means no events occurred.
- **Bare field vs `*_raw`.** Numeric fields often render as a human-formatted
  string (`latency_ns`="1.2ms", `memoryRSS`="12 MB", `throttledTime`="4ms"); the
  `_raw` sibling (`latency_ns_raw`, `memoryRSS_raw`, `throttledTime_raw`) is the
  machine number — use `_raw` for arithmetic/sort/`jq` comparisons, the bare
  field for display. Both appear under `-h`/`--fields`.
- **In-cluster IG must be present.** `kubectl gadget run` needs the IG DaemonSet
  (or `kubectl gadget deploy`). If commands hang or error on connectivity, verify
  `kubectl get pods -n gadget`.
