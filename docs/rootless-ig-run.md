# Running `ig` Rootless

Run `ig` as a normal (non-root) user with scoped capabilities instead of `sudo`.

## 1. Host setup

These steps require `sudo` **once**. Some are not persistent across reboots (see notes).

### a) Allow your user to read tracefs

`ig` needs to read tracepoint IDs under `/sys/kernel/tracing`.

```bash
sudo chmod -R o+rX /sys/kernel/tracing
```

> ⚠️ Resets on reboot (tracefs is a pseudo-filesystem) — re-run after each boot, or
> persist it with a systemd oneshot. Exposes system-wide tracing data to all local
> users; acceptable on dev/dedicated hosts, reconsider on multi-tenant machines.

### b) Set `perf_event_paranoid`

```bash
sudo sysctl -w kernel.perf_event_paranoid=2
```

### c) Grant capabilities to the `ig` binary

```bash
sudo setcap cap_sys_ptrace,cap_perfmon,cap_bpf=eip ./ig
```

| Capability       | Purpose                                              |
| ---------------- | ---------------------------------------------------- |
| `cap_bpf`        | Load eBPF programs and create maps                   |
| `cap_perfmon`    | Open tracepoint perf events                          |
| `cap_sys_ptrace` | Read `/proc/<pid>/ns/*` for container enrichment     |

> ⚠️ Capabilities are bound to the file inode. **Re-run `setcap` after every rebuild.**

Verify:

```bash
getcap ./ig   # → ./ig cap_sys_ptrace,cap_perfmon,cap_bpf=eip
```

## 2. Using `ig` with Podman

Enable the rootless Podman API socket (once):

```bash
systemctl --user enable --now podman.socket
ls -l "$XDG_RUNTIME_DIR/podman/podman.sock"
```

Run `ig`, pointing it at the rootless socket:

```bash
./ig run trace_exec:built-rootless \
  --oci-store-user \
  --verify-image=false \
  -r podman \
  --podman-socketpath "$XDG_RUNTIME_DIR/podman/podman.sock"
```

> Only containers started by **your** user (rootless Podman) are visible.

## 3. Drawbacks

- **No new-container detection.** Rootless `ig` lacks `CAP_SYS_ADMIN`, so fanotify is
  unavailable. Only containers **already running before `ig` starts** are detected and
  enriched; containers created afterwards will not appear.

  ```
  WARN  binary does not have CAP_SYS_ADMIN: new containers will not be detected
  ```
