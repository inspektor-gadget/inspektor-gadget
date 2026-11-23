# container-hook: permission-event gatekeeper

The container hook (`pkg/container-hook`) detects containers with fanotify
permission events: `FAN_OPEN_EXEC_PERM` on the OCI runtime binary (every runc
call) and `FAN_ACCESS_PERM` on pid-file directories (container create→start).
The kernel blocks the process that triggered the event until the fanotify
reader answers, and there is no timeout. If the reader is alive but cannot make
progress (throttled in memcg reclaim, CPU-starved, stopped), every container
start, stop and exec on the host blocks, kubelet cannot restart the reader
through the same runtime, and the node stays `Ready`.

The gatekeeper bounds that wait. It is a small separate process that reads both
fanotify groups and answers every permission event when the container hook is
done with it, or when the bound expires, whichever comes first.

## Flow

1. `install()` loads the eBPF program, then starts the gatekeeper before adding
   any mark. It passes the two fanotify fds, the `ig_fa_records` map fd and one
   end of a `SOCK_SEQPACKET` socket pair, and waits (up to 30s) for the
   gatekeeper's ready message: protocol version, and the cgroup it moved to or
   why it could not. On a version mismatch, a timeout or an early exit, the
   hook stops the gatekeeper and answers in-process instead.
2. The gatekeeper reads an event. For the runtime group it dequeues the
   matching `ig_fa_records` entry right away, which keeps the events and
   records in lockstep.
3. It sends the event to the hook: a 24-byte header, the record, and the event
   fd as `SCM_RIGHTS`. The send never blocks. If the socket is full, the
   gatekeeper allows the event at once and drops it.
4. The hook processes the event as before (marks, pid-file read through its copy
   of the event fd, AddContainer callback) and replies with the event's
   sequence number.
5. The gatekeeper answers `FAN_ALLOW` on the reply, or at the deadline, and
   closes its copy of the event fd. The fd stays open until then, so its number
   cannot be reused by another pending event.

The hook never reads or answers the fanotify groups itself while a gatekeeper
runs.

## Bounds

| Group | Bound | Set by |
|---|---|---|
| runtime binary (every runc call) | 1s | `SetPermissionResponseBound` (100ms–60s) |
| pid file (create→start, held while the AddContainer callback runs) | 3s | `SetPidFileResponseBound` (100ms–60s) |

## Process and cgroup

- Binary, first that starts and sends a valid ready message (one that fails
  to start, exits early or speaks another protocol version is stopped and the
  next one is tried):
  1. `IG_CONTAINER_HOOK_GATEKEEPER_BIN`, if set (and nothing else);
  2. the copy embedded with `-tags gatekeeper_embed`, run from a sealed memfd
     (`make ig` and the `ig` image embed it, so the `ig` CLI needs no install
     step); it always speaks the library's protocol;
  3. `/usr/bin/ig-container-hook-gatekeeper` (`cmd/container-hook-gatekeeper`,
     ~1.7 MB, ~2 MB RSS), as shipped in the gadget image;
  4. this binary, re-executed: an `init()` in `pkg/container-hook` runs the
     gatekeeper before `main`. That works for any library user, but the
     process pays for its package initialization, charged to the caller's
     cgroup, so the hook logs a warning.
- Session: the gatekeeper runs in a session of its own, so terminal job
  control on an `ig run` (Ctrl-Z, Ctrl-C) never stops or kills it. Ctrl-Z on
  `ig run` was the easiest way to freeze a host before.
- Cgroup: the gatekeeper moves itself into its own child,
  `<host root>/sys/fs/cgroup/ig-container-hook-gatekeeper/<pid>`, always when
  the caller runs containerized (`HOST_ROOT` is not `/`: its cgroup can be
  frozen or limited by the runtime at any time), and from a host shell only
  when the caller's cgroup or an ancestor has a `memory.max`, `memory.high` or
  `cpu.max` limit. The child gets generous limits (`memory.max` 256Mi,
  `pids.max` 512, `cpu.max` 1 CPU) that only bound a misbehaving one. Reading an event charges its `struct file` to
  the reader's memcg, so a gatekeeper left in the hook's memcg is throttled
  with it. The limits stay far above what it uses because the kernel answers
  `FAN_DENY` when it cannot create a permission event's fd for the reader.
  - The hook usually runs in a private cgroup namespace, which forbids
    migrating out of it, so the move is done from a locked thread that first
    joins the host cgroup namespace through `/proc/1/ns/cgroup` (requires
    hostPID).
  - If the move fails (cgroup v1, no hostPID), the gatekeeper stays and the
    hook logs a warning from the ready message.
  - On a normal exit the gatekeeper moves to the root cgroup and removes its
    child (the hook may have exited without waiting for it, as a CLI does on
    Ctrl-C); the hook also removes it once the gatekeeper exited. A
    gatekeeper that was killed leaves its child to the next one, which, once
    it moved, removes the empty children of gatekeepers that are gone. Only
    names it creates (`<pid>` or `<pid>-<n>`) are ever removed, so an
    overridden base shared with other cgroups is safe. The empty
    `ig-container-hook-gatekeeper` directory stays on the host after
    uninstall.
  - From an unconstrained host shell nothing is created and it stays in the
    caller's cgroup. If it cannot confirm where it is (no hostPID, so the host
    cgroup namespace is out of reach), it assumes constrained and tries; the
    failure is logged as a warning by the hook.
  - `IG_CONTAINER_HOOK_GATEKEEPER_CGROUP_DIR` sets the base directory and
    forces the move even without a limit; `none` disables the move.
- The gatekeeper closes any other fanotify group fd it inherited, so it never
  keeps a group alive that the hook closed, and raises its `RLIMIT_NOFILE` soft
  limit for the up to 4096 pending event fds it holds.
- It ignores SIGTERM, SIGINT, SIGHUP and SIGQUIT (`pkill ig` also matches
  `ig-gatekeeper`): it exits when the hook's socket closes, after allowing
  everything it holds.
- It locks its memory (`mlockall`, on fault): the embedded binary's pages live
  in a memfd charged to the caller's memcg and must not be faulted back in
  under the caller's memory pressure.

## Failure behavior

| What fails | Result |
|---|---|
| Hook stuck or slow | Events allowed at the bound; those containers may be missed. If a watcher falls 1024 events behind, the hook drops further forwarded events and the gatekeeper allows them at the bound |
| Hook exits | Socket closes; the gatekeeper allows everything pending and exits |
| Gatekeeper exits | The hook notices the process exit (not a socket EOF, which would only come after every queued message) and closes its fanotify fds; the kernel drops the marks and allows pending events. Detection stops, container lifecycle keeps working |
| Gatekeeper cannot start, or is not ready within 30s, or speaks another protocol version | The hook answers in-process, without a deadline, and logs a warning |

The gatekeeper only ever allows. It never denies an event.

`IG_CONTAINER_HOOK_GATEKEEPER_DISABLE=1` turns the gatekeeper off and restores
in-process answering.

## Logs

The gatekeeper writes to a pipe of its own, without blocking (a line is
dropped rather than stall the gatekeeper), and the hook relays each line to its
log:

- `container-hook gatekeeper: running in cgroup ...`, or why it stayed
- `container-hook gatekeeper: started (pid ..., bounds: ...)`
- `container-hook gatekeeper: fail-open: expired=N dropped=N evicted=N (forwarded=N answered=N)`,
  at most every 10s and only when a fail-open counter changed

Issue: #5996.
