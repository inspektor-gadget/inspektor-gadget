# Domain: security (capabilities / LSM / seccomp / module loading)

Route here for: "permission denied" despite correct file perms/RBAC, seccomp /
AppArmor / SELinux denials, a container needing an unexpected capability, or
unexpected kernel-module loads. Confirm flags/fields with
`kubectl gadget run <gadget>:latest -h`. Flags below are verified against the
shipped images.

## Which gadget for which denial

- **`trace_capabilities`** — records every kernel **capability check** (the
  `capable()` LSM hook): which `CAP_*` was tested and whether it was allowed.
  Use when an operation fails with EPERM but file perms look right — you'll see
  exactly which capability the workload is missing (e.g. `CAP_NET_ADMIN`,
  `CAP_SYS_PTRACE`).
  Verified flags: `--audit-only` (only audit checks), `--unique` (collapse
  repeats per container), `--filter/-F`, `--pid`, `--uid`, `--gid`.
- **`trace_lsm`** — records that an **LSM hook was invoked** (effectively "strace
  for LSM hooks"). It emits process identity plus the `tracepoint` name, but not
  another LSM's return value, so it cannot by itself prove that AppArmor or
  SELinux denied an operation. Use node audit logs for the verdict; use
  `trace_lsm` only to correlate hook activity. `--trace-all` defaults to false,
  so pass it or a specific `--trace-<hook>` flag.
- **`audit_seccomp`** — records seccomp audit events with the syscall and
  seccomp `code` (for example ERRNO, TRAP, KILL, USER_NOTIF, or LOG). Use the
  code to distinguish a denial from a logged/notification action.
- **`advise_seccomp`** — records syscalls during a representative workload and
  emits suggested profiles when the run stops. Its supported/default output mode
  is `advise`, not JSON. Redirect the default output to a text file; it can contain
  one labeled JSON profile per container.
- **`trace_init_module`** — `init_module`/`finit_module`: **kernel module loads**.
  Use for security auditing ("did anything load a module?") or module-load fails.
  **From inside a container or from the host?** — that is the real security
  question. A non-empty `k8s.containerName` (kubectl) / `runtime.containerName`
  (`ig`) means a container loaded it; an empty one under `--host` means a host
  process. Always read that column, not just "a module loaded".

## "Permission denied" decision flow

```bash
# 1. Which capability is being denied? (EPERM with correct FS perms)
kubectl gadget run trace_capabilities:latest -n <ns> -p <pod> --timeout 15 \
  -o columns --fields k8s.podName,proc.comm,cap,capable,syscall
# 2. If it's a seccomp action, inspect the audited syscall and return code
kubectl gadget run audit_seccomp:latest -n <ns> --timeout 15 -o json
# 3. For AppArmor/SELinux, inspect node audit logs for the verdict.
# Optional: correlate which LSM hooks the workload reaches (activity only).
kubectl gadget run trace_lsm:latest -n <ns> --trace-all --timeout 15 -o json
```

Read: in step 1, a row where `capable=false` names the missing `cap`; first fix
why it is requested, and grant it only when that access is intended. In step 2,
read both `syscall` and `code`; not every audited action is a denial. In step 3,
the node's AppArmor/SELinux audit record supplies the actual allow/deny verdict.
`trace_lsm` only confirms that a named hook ran.

## Least-privilege authoring (not just debugging)

1. Run `advise_seccomp` while exercising a representative workload window:
   `kubectl gadget run advise_seccomp:latest -n <ns> -p <pod> --timeout 30 >
   seccomp-advice.txt`.
2. Select and review the labeled profile for the intended container. The advisor
   only permits syscalls observed during that window, so incomplete workload
   coverage produces an incomplete profile.
3. Use `advise_networkpolicy` (networking domain) for the network side.

This turns IG from a debugger into a **hardening** tool — observe real behavior,
then generate the minimal policy that permits exactly it.

## Notes

- `trace_capabilities`/`trace_lsm`/`audit_seccomp` are streaming — bound with
  `--timeout`; scope with `-n`/`-p`/`-c` (security traffic is high-volume).
- `--audit-only` on `trace_capabilities` cuts to the checks that matter for
  audit; `--unique` stops the same capability spamming once per container.
- The full LSM hook list is huge — use a specific `--trace-<hook>` when you know
  it. To **discover which hooks are actually firing**, run briefly with
  `--trace-all` and tabulate the `tracepoint` field:

  ```bash
  kubectl gadget run trace_lsm:latest -n <ns> --trace-all --timeout 15 -o json \
    | jq -r '.tracepoint' | sort | uniq -c | sort -rn
  ```
