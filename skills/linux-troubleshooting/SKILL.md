---
name: linux-troubleshooting
description: >-
  Debug a single Linux host, VM, or container runtime at the kernel level with
  Inspektor Gadget via the standalone `ig` binary — no Kubernetes required. Use
  when something on a bare host, edge node, CI runner, or Docker/containerd/CRI-O
  box is failing and logs aren't enough: DNS or TCP failures, connection resets /
  retransmits / drops, processes exiting or being killed (OOM/signal), failed or
  missing file opens, permission / capability / seccomp / LSM denials, slow disk
  or file I/O, or "which process made this syscall / connection". Traces real
  kernel events with eBPF; enriches with container name/runtime when a runtime is
  present. Read-only. Not for Kubernetes clusters (use kubernetes-troubleshooting
  for `kubectl gadget`), plain application logs, or metrics dashboards.
compatibility: >-
  Requires the standalone `ig` binary on PATH, run as root (CAP_BPF +
  CAP_SYS_ADMIN), on a BTF-enabled kernel (`/sys/kernel/btf/vmlinux`) for CO-RE. An
  optional container runtime (containerd/Docker/CRI-O/podman) enriches events;
  `--host` traces bare-host processes. Read-only. If `ig` is missing, see
  references/install.md — ask the operator before installing.
---

# Linux host / container-runtime troubleshooting with Inspektor Gadget

The standalone `ig` binary runs the **same eBPF gadgets** as the Kubernetes
integration, but against a **single Linux host** and its local container runtime
(Docker / containerd / CRI-O / podman) — no cluster, no `kubectl`. Use it on
VMs, edge nodes, CI runners, or any box where you can run `sudo ig`. Events are
enriched with **container name + runtime** (not pod/namespace) when a runtime is
present; with `--host` you also see host (non-container) processes.

Reach for `ig` when host logs/metrics can't answer *"what is the kernel doing
right now?"* — a syscall failing silently, a connection reset before the app
notices, a file open returning ENOENT.

## Prerequisite: confirm IG is available (check first, then route)

This skill drives the standalone `ig` binary. Confirm it's usable before the loop:

```bash
command -v ig >/dev/null 2>&1 && ig version || echo "ig MISSING -> references/install.md"
```

If `ig` is **missing**, **open `references/install.md` and follow it** — don't guess
an install command. `ig` needs root (CAP_BPF / CAP_SYS_ADMIN) and a BTF-enabled
kernel; **ask the operator before installing on a host you don't own**.

## The one rule: discover, don't guess

**Never hardcode a gadget's flags or field names from memory.** Enumerate the
real interface at run time:

```bash
sudo ig run <gadget>:latest --help       # flags + a "--fields" block listing every data source & field
sudo ig run <gadget>:latest --timeout 5 -o json | jq '.[0] | keys'   # real field names in a live sample
```

Each gadget is an OCI image pulled on demand; there is **no `list-gadgets`
command** and no fixed list to memorize. The gadget's own `--help`/`--fields` is
the source of truth. See `references/discovering-params-and-fields.md`.

## The loop (repeat until root cause)

1. **Route.** Map the symptom to a *domain* (networking / security /
   process-lifecycle / storage-fs / performance) and a candidate gadget using
   the table below + `references/gadget-catalog.md`.
2. **Discover.** Run `<gadget>:latest --help` to read the real flags and fields.
3. **Run bounded.** Scope and time-box:
   `sudo ig run <gadget>:latest --runtimes containerd -c <name> --timeout <sec> -o json`
   (`-c` filters by container, `--comm`/`--pid` by process; add `--host` for host
   processes; **always set `--timeout`**; `--max-entries` for `top`/`snapshot`).
   See `references/common-flags.md`.
4. **Read the columns.** Inspect the fields (`runtime.*`, `proc.*`, error codes)
   to confirm or refute, then narrow and repeat.

## Symptom → first gadget (confirm flags/fields with `--help`)

| Symptom | Domain | Start with | Then / disambiguate |
|---|---|---|---|
| DNS fails / slow / NXDOMAIN | networking | `trace_dns` | latency in `latency_ns` |
| Connection reset / refused / hangs | networking | `trace_tcp` | `trace_tcpretrans`, `trace_tcpdrop` |
| Packet loss / high latency | networking | `trace_tcpdrop` | `profile_tcprtt`, `top_tcp`, `tcpdump` |
| TLS/cert/SNI issue | networking | `trace_sni` | `trace_ssl` |
| Port bind fails / "address already in use" | networking | `snapshot_socket` | `trace_bind` (bind + errno) |
| Process exits / restarts unexpectedly | process-lifecycle | `trace_exec` | `trace_signal` (filter `--signal 9/15` — Go SIGURG / glibc SIGRTMIN async-preempt noise), `trace_oomkill` |
| Process killed / OOM | process-lifecycle | `trace_oomkill` | `top_process`, `profile_cpu` |
| Container died too fast to trace live (post-mortem) | process-lifecycle | `traceloop` | replays recent syscalls from the ring buffer; empty if it wasn't already recording |
| Watch an interactive shell / tty / pts / keystrokes | process-lifecycle | `ttysnoop` | no `--tty`/`--pts` selector — scope by `--pid`/`--comm`/container |
| "no such file" / missing path | storage-fs | `trace_open --failed` | `snapshot_file`, `top_file` |
| Slow disk / file I/O | storage-fs | `trace_fsslower` | `profile_blockio`, `top_blockio` |
| Unexpected mount/umount, or suspicious hardlink/symlink (escape) | storage-fs | `trace_mount` | `trace_link` (`type` = HARDLINK/SYMLINK cuts the noise) |
| fd leak / "too many open files" / inotify watch storm | storage-fs | `fdpass` | `fsnotify`; `snapshot_file` (unclosed fds in one proc) |
| Permission denied despite correct FS perms | security | `trace_capabilities` | `trace_lsm`, `audit_seccomp` |
| Seccomp/AppArmor/SELinux denial | security | `trace_lsm` | `audit_seccomp`, `advise_seccomp` |
| Syscall blocked by a seccomp profile ("operation not permitted") | security | `audit_seccomp` | the audited syscall = what the profile forbids; `advise_seccomp` to author one |
| Kernel module loaded / rootkit / unexpected insmod | security | `trace_init_module` | `trace_capabilities` (CAP_SYS_MODULE) |
| Harden / author a seccomp or NetworkPolicy profile | security | `advise_seccomp` | `advise_networkpolicy` |
| High CPU, or slow despite low CPU% (CFS throttling / cgroup CPU limit) | performance | `profile_cpu` | `top_cpu_throttle` (capped?), `top_process` |
| Memory growth / leak (userspace) | performance | `trace_malloc` (libc malloc only — statically-linked Go runtime allocator invisible) | `trace_malloc --collect-ustack` (the leak site) |
| App hung / mutex deadlock | performance | `deadlock` (pthread only — Go `sync.Mutex` invisible) | `profile_cpu` |
| GPU / CUDA out-of-memory | performance | `top_cuda_memory` | device vs pinned; `profile_cuda` = libcuda Driver-API |
| Quantify eBPF/gadget CPU or memory overhead (self-profiling) | meta | `bpfstats` | needs an active window — longer `--timeout` |

This is a deliberately **thin shortlist, not the catalog** — it names the few
gadgets that fit the most common symptoms so you don't scan all ~42, keeping this
always-loaded router small. **Symptom not listed, or
unsure which row fits?** Read `references/gadget-catalog.md` — it groups **all
42** gadgets by domain with the disambiguation reasoning (which of the
TCP/file/TLS/CPU gadgets to pick). The authoritative live list is whatever `sudo
ig run <name>:latest --help` resolves; confirm a gadget's flags/fields there
before relying on them.

## References (load only the one you need)

- `references/gadget-catalog.md` — all upstream gadgets grouped by domain, with per-domain disambiguation.
- `references/discovering-params-and-fields.md` — discover-don't-guess mechanics (`ig` variant).
- `references/common-flags.md` — host/container scope, output, timeouts, gotchas.
- `references/install.md` — detect whether `ig` is usable; install it + requirements (root, BTF) if missing.
- `references/kubernetes-companion.md` — when to switch to `kubectl gadget` (clusters).

### Per-domain deep-dive playbooks (shared with the k8s skill)

The five per-domain playbooks (networking, security, process-lifecycle,
storage-fs, performance) live in the **kubernetes-troubleshooting** skill's
`references/` tree and apply verbatim here — **the gadgets, flags, and fields are
identical**; only the launcher and scope flags differ. To use one from this
single-host skill, swap `kubectl gadget run`→`sudo ig run` and `-n`/`-p`→
`-c`/`--host` (full mapping in `references/kubernetes-companion.md`):

- `../kubernetes-troubleshooting/references/domain-networking.md` — DNS / TCP / drops / retransmits / TLS-SNI / pcap / NetworkPolicy.
- `../kubernetes-troubleshooting/references/domain-security.md` — capabilities / LSM / seccomp / kernel-module loading.
- `../kubernetes-troubleshooting/references/domain-process-lifecycle.md` — exec / signals / OOM / snapshots / traceloop / tty.
- `../kubernetes-troubleshooting/references/domain-storage-fs.md` — open / slow FS / block I/O / mounts / links / fd / fsnotify.
- `../kubernetes-troubleshooting/references/domain-performance.md` — CPU / throttle / RTT / deadlock / malloc / GPU.

## Safety

Observation is **read-only** — gadgets never modify the host or containers. `ig`
needs elevated privileges (typically `sudo`, CAP_BPF/CAP_SYS_ADMIN) to load eBPF.
Always bound streaming gadgets with `--timeout` and cap `top`/`snapshot` with
`--max-entries`.
