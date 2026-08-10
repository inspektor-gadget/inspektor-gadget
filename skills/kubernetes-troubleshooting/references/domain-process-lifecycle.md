# Domain: process lifecycle (exec / signals / OOM / snapshots / recording)

Route here for: CrashLoopBackOff, containers exiting or restarting unexpectedly,
"who killed my process", OOMKilled, unexpected binaries running, or a
point-in-time view of what's running. Confirm every gadget's flags/fields with
`kubectl gadget run <gadget>:latest -h`.

## The three "why did it die / start" gadgets

- **`trace_exec`** — every process execution (argv, uid, cwd with `--paths`).
  Use for CrashLoopBackOff to see **what the container actually execs** and with
  which arguments — a wrong entrypoint, a failing init binary, or an unexpected
  child shows here immediately.
- **`trace_signal`** — signals delivered between processes. Use for "container
  got SIGKILL/SIGTERM out of nowhere": see the **sender** (`proc.comm`/pid), the
  **target** pid (`tpid`), and the `sig` number (`sig_raw` = numeric value).
- **`trace_oomkill`** — OOM-killer events: victim `tcomm`/`tpid` (the killed process — NOT the
  trigger `fprocess.comm`/`fprocess.pid`, which is whoever's allocation tripped
  the OOM) and the memory cgroup. Definitive answer to "was this an OOM kill?" (vs a signal or a clean
  exit).

Decision order for a dying container: `trace_oomkill` (was it OOM?) →
`trace_signal` (was it signalled, by whom?) → `trace_exec` (did it even start,
with what argv?).

## CrashLoopBackOff worked flow

```bash
# 1. What is the container exec-ing? (catch a failing entrypoint/argv)
kubectl gadget run trace_exec:latest -n <ns> -p <pod> --ignore-failed=false \
  --paths --timeout 15 \
  -o columns --fields k8s.podName,proc.comm,args,error
# 2. Is something signalling it?
kubectl gadget run trace_signal:latest -n <ns> --timeout 15 \
  -o columns --fields k8s.podName,proc.comm,sig,tpid
# 3. Is it an OOM kill?
kubectl gadget run trace_oomkill:latest -A --timeout 20 -o json
```

Read: `trace_exec` ignores failed executions by default, so step 1 explicitly
sets `--ignore-failed=false`. A non-zero `error` (e.g. ENOENT/EACCES) means the
binary/path is wrong or not executable — a classic CrashLoop cause the app logs
never show. In step 2, a `SIGKILL` from a non-kubelet `proc.comm` points at a
sidecar/supervisor. In step 3, any row = confirmed OOM (raise limits / fix leak;
pivot to `trace_malloc`).

## Point-in-time snapshots (state, not stream)

- **`snapshot_process`** — list processes running *right now* in scope. Use to
  confirm whether a process you expect is actually alive, or spot an unexpected
  one. `--max-entries` to cap. **Also pass `--timeout`** — although snapshots are
  "one-shot", `snapshot_process` can hang waiting on node/DaemonSet responses
  (observed >2min without one), so always bound it. For columns, use
  `-o columns --fields …,parent.comm` (the `-o columns=field,field` comma form is
  parsed as separate output modes and silently drops everything — see
  `common-flags.md`); `-o json` + `jq '.[].parent.comm'` also works for nested fields.
- **`top_process`** — periodic process stats (CPU/mem ranking) — "what's hot
  right now". Verified flags: `--sort` (join with `,`; `-` prefix = descending,
  e.g. `--sort -memoryRSS` for the biggest memory users), `--interval` (default
  `3s`), `--count` (number of reports; `0` = until timeout), `--max-entries`.
  Memory columns `memoryRSS`/`memoryVirtual`/`memoryShared` (each with a `_raw`
  numeric sibling); CPU `cpuUsage`/`cpuUsageRelative`.

```bash
# Top memory consumers in a namespace, refreshed every 5s
kubectl gadget run top_process:latest -n <ns> --sort -memoryRSS --interval 5 --max-entries 10 -o json
```

## Flight recorder

- **`traceloop`** — a syscall flight recorder: continuously records recent
  syscalls per container so you can **replay the last syscalls before a crash**.
  Invaluable when a container dies too fast to attach a live trace: the ring
  buffer already holds what it did. Read `-h` for the record/dump workflow.

## `ttysnoop`

- Watch live output from a tty/pts device (e.g. what an interactive debug session
  is printing). Niche; use when you need to observe a specific terminal.

## Notes

- All of these are **read-only**. `trace_exec`/`trace_signal` are streaming —
  bound with `--timeout`. `snapshot_*` are one-shot but cap with `--max-entries`.
- Scope tightly (`-n`/`-p`/`-c`): exec/signal traffic cluster-wide is very noisy
  and will bloat context.
