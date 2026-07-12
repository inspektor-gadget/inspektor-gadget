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
- **`trace_lsm`** — decisions at **LSM hooks** — effectively "strace for LSM".
  Use for AppArmor/SELinux/BPF-LSM denials to see which hook (e.g.
  `bprm_check_security`, `file_open`, `inode_permission`) returned a denial.
  Verified: `--trace-all` (default true) or per-hook `--trace-<hook>` flags to
  scope to a single hook; `--filter/-F`.
- **`audit_seccomp`** — syscalls **audited/blocked by the seccomp profile**. Use
  when a container dies or an op fails and you suspect the seccomp profile is too
  strict — you'll see the offending syscall.
- **`advise_seccomp`** — after tracing, **suggest a seccomp profile** from the
  syscalls actually used (least-privilege authoring). It emits the profile on the
  data stream — capture it with `-o json > profile.json` (redirect stdout), not
  an in-place file. `audit_seccomp` likewise streams; persist with
  `-o json > audit.json`. Confirm the exact output flags with `-h`.
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
  -o columns=k8s.podName,proc.comm,cap,capable,syscall
# 2. If it's an LSM/AppArmor/SELinux denial, see the hook decision
kubectl gadget run trace_lsm:latest -n <ns> --timeout 15 -o json
# 3. If it's a seccomp block, see the audited syscall
kubectl gadget run audit_seccomp:latest -n <ns> --timeout 15 -o json
```

Read: in step 1, a row where `capable=false` names the missing `cap` — add it to
the container's `securityContext.capabilities` (or fix why it's requested). In
step 2, the denied hook + `proc.comm` tells you which action the LSM blocked. In
step 3, the audited `syscall` is what the seccomp profile forbids.

## Least-privilege authoring (not just debugging)

1. Run the workload under `trace_capabilities` and `audit_seccomp` through a
   representative workload window (bounded `--timeout`).
2. Feed observations to `advise_seccomp` to generate a tight seccomp profile.
3. Use `advise_networkpolicy` (networking domain) for the network side.

This turns IG from a debugger into a **hardening** tool — observe real behavior,
then generate the minimal policy that permits exactly it.

## Notes

- `trace_capabilities`/`trace_lsm`/`audit_seccomp` are streaming — bound with
  `--timeout`; scope with `-n`/`-p`/`-c` (security traffic is high-volume).
- `--audit-only` on `trace_capabilities` cuts to the checks that matter for
  audit; `--unique` stops the same capability spamming once per container.
- The full LSM hook list is huge — start with `--trace-all` and filter the JSON
  by the hook you care about, or pass the specific `--trace-<hook>` flag. To
  **discover which hooks are actually firing** (rather than guessing a hook name),
  enumerate the live distinct values — find the hook field with `jq keys` first,
  then tabulate:

  ```bash
  kubectl gadget run trace_lsm:latest -n <ns> --trace-all --timeout 15 -o json > /tmp/lsm.json
  jq '.[0] | keys' /tmp/lsm.json                 # locate the hook field (e.g. name)
  jq -r '.[].name' /tmp/lsm.json | sort | uniq -c | sort -rn
  ```
