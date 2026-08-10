# Domain: performance (CPU / throttle / RTT / deadlock / malloc / GPU)

Route here for: high CPU, CPU throttling, latency, memory growth/leaks, hangs
(deadlock), or GPU memory issues. Confirm flags/fields with
`kubectl gadget run <gadget>:latest -h`. Flags below are verified against the
shipped images.

## CPU: where is it going vs who is being capped

- **`profile_cpu`** — samples stack traces → an **on-CPU profile** (flamegraph
  input). Use to answer "*where* is CPU being spent" (which functions/stacks).
  Verified flags: `--user-stacks-only`, `--kernel-stacks-only` (scope the stack),
  `--include-idle`, `--sort`. **Omit BOTH stack flags to get the combined
  kernel+user stack** — the full flame graph; pass exactly one to halve the volume
  when you only care about the app (user) or the kernel. To visualise, collapse the
  sampled stacks to folded format (`func;func;… count`) and render with Brendan
  Gregg's FlameGraph (`flamegraph.pl`, github.com/brendangregg/FlameGraph) — the
  folding is a post-process step, `profile_cpu` has no `--fold` flag.
- **`top_cpu_throttle`** — cgroup **CFS throttling** stats: containers hitting
  their CPU *limits* and being throttled. Use to answer "is the app slow because
  it's being **capped**" (a config/limits problem, not a hot-code problem).
  Verified flags: `--interval`, `--count`, `--sort`. The decisive signal is the
  throttle counters — a non-zero throttled *count* and throttled *time* mean the
  app is being paused by CFS. Confirm the exact field names with `-h`/`--fields`
  before scripting (they are camelCase and can shift by image version — don't
  hardcode them from memory).
- **`top_process`** — periodic process CPU/mem ranking — "*who* is hot".

Decision: app is slow → `top_cpu_throttle` (are we being throttled by limits?) →
if not, `profile_cpu` (where is the CPU actually going?) → `top_process` (which
process).

```bash
# Is this workload being CPU-throttled by its limits?
kubectl gadget run top_cpu_throttle:latest -n <ns> --timeout 15 -o json
# Where is the CPU going (user stacks only, for an app profile)?
kubectl gadget run profile_cpu:latest -n <ns> -p <pod> --user-stacks-only --timeout 20 -o json
```

Read: a non-zero throttled count/time in `top_cpu_throttle` means **raise the CPU
limit or reduce work** — the app isn't "slow", it's being paused by CFS. If
throttling is zero, use `profile_cpu` to find the hot stack.

## Memory (userspace)

- **`trace_malloc`** — libc `malloc`/`free` via **uprobe** (it hooks the libc
  allocator, so it sees only userspace allocations that go through libc — not raw
  `mmap`/`brk`, nor a musl-static binary; that's the attach caveat). **Scope it** —
  a uprobe on every process is expensive and noisy — with **`--comm <name>`** or
  **`--pid <pid>`** to the suspect process. Add **`--collect-ustack`** to capture
  the **allocation call stack** (the leaking *site*), so `trace_malloc` itself
  answers "where is the leak". Do **not** hop to `profile_cpu` for allocation stacks
  — `profile_cpu` is an on-CPU profiler with no allocation-profiling mode (the older
  "find the alloc site with profile_cpu" pointer was inaccurate). Pair with
  `trace_oomkill` (process-lifecycle) when the workload is OOM-killed to confirm a
  userspace leak first.

## Latency

- **`profile_tcprtt`** — TCP RTT histogram (also in networking): use here when
  "latency" is network-round-trip, not CPU.
- **`profile_qdisc_latency`** — network scheduler latency (egress shaping).

## Hangs / deadlocks

- **`deadlock`** — builds a per-process **lock graph** from
  `pthread_mutex_lock`/`unlock` ordering to surface **lock-order inversions**. Use
  when a multithreaded app hangs with no crash and no CPU (a classic mutex
  deadlock). Verified flags: **`--pid <pid>`** / **`--comm <name>`** — scope to the
  **suspect process** (the graph is per-process; an unscoped run is noise). You must
  **reproduce the hang while the gadget is attached** — it builds the graph from
  live lock operations, so a mutex acquired before you attached is invisible.
  Caveat: it instruments **`pthread_mutex` only** — a Go `sync.Mutex` or an async
  runtime that bypasses pthread won't appear (corroborate a stall with `profile_cpu`
  stack sampling).

## GPU (CUDA)

- **`top_cuda_memory`** — per-process CUDA memory alloc/free ranking. The decisive
  field is **`host`** = *Memory class* (**`DEVICE` = GPU VRAM, `HOST` = pinned host
  memory**) — so you can tell GPU-VRAM exhaustion from a pinned-host-memory balloon
  at a glance. Scope per process with **`--pid`** / **`--comm`** (the CUDA gadgets
  are uprobes on the CUDA libraries — scope them). Use for "GPU OOM / who is holding
  **device** memory".
- **`profile_cuda`** — CUDA allocation/free behavior over time in libcuda (Driver
  API) — deeper allocation *profiling*. Like `top_cuda_memory` it's a uprobe on
  the CUDA libraries, so scope per process with `--pid`/`--comm`; confirm its
  fields/flags with `-h` (it tracks alloc size/kind over the run).

```bash
# Who is holding CUDA device memory? (host=DEVICE vs HOST distinguishes VRAM vs pinned)
kubectl gadget run top_cuda_memory:latest -n <ns> --timeout 15 -o json
```

**Disambiguate the CUDA question:** `top_cuda_memory` = capacity / top holders (who
holds how much, `DEVICE` vs `HOST`); `profile_cuda` = alloc/free behavior over time.
**Neither diagnoses an "illegal memory access" / out-of-bounds CUDA error** — that's
a kernel-*code* bug (bad pointer/index), not a memory-capacity gadget target; don't
assume an OOM and an illegal-access share one root cause. For that class, hand
off to CUDA's own tools — **`compute-sanitizer`** (its `memcheck`/`racecheck`
tool) or **`cuda-gdb`** — which pinpoint the offending kernel/line; IG's job is
only to rule OUT a memory-capacity/OOM cause first.

## Notes

- `profile_*` and `top_*` are sampling/periodic — bound with `--timeout` and cap
  `top_*` with `--max-entries`/`--count`.
- `profile_cpu` output is stacks; project/aggregate rather than dumping every
  sample into context. Use `--user-stacks-only` to halve the volume
  when you only care about the app.
