# Domain: storage & filesystem (open / slow I/O / block / mounts / fd / notify)

Route here for: "no such file or directory", missing/wrong config paths, EACCES
on files, slow disk or file I/O, mount problems, or "which process is hammering
this file". Confirm flags/fields with `kubectl gadget run <gadget>:latest -h`.
Flags below are verified against the shipped images.

## The file-access trio (don't conflate)

- **`trace_open`** — the `open`/`openat` **call itself**: filename, flags, and the
  **error** (errno). This is the first stop for "no such file", wrong path, or
  permission-denied-on-a-file. Verified flag: **`--failed`** (show only failed
  opens) — the single best noise-cutter when hunting a missing/denied file.
- **`snapshot_file`** — point-in-time list of **currently open files** in scope.
  Use to answer "does this process actually have the file open / which fd". Verified
  flags: `--type-mask` (filter by file type), `--sort`.
- **`top_file`** — periodic **read/write activity per file** — "what file is hot".
  Verified flags: `--all-files` (by default only regular files are traced),
  `--sort` (e.g. `--sort -wbytes` = busiest writers first; fields
  `wbytes`/`rbytes`/`writes`/`reads`, each with a `_raw` numeric sibling),
  `--max-entries`. The `comm`/`pid` columns name the process doing the I/O:

```bash
# Which process is writing the most, per file?
kubectl gadget run top_file:latest -n <ns> --sort -wbytes --max-entries 10 \
  -o columns --fields k8s.podName,comm,pid,file,wbytes,rbytes
```

Rule of thumb: *open is failing* → `trace_open --failed`; *what's open now* →
`snapshot_file`; *what's busy* → `top_file`.

## "No such file / config not found" worked flow

```bash
# Show only FAILED opens — read fields via json (see the columns pitfall below),
# filtering out the benign glibc dynamic-loader ENOENT noise
kubectl gadget run trace_open:latest -n <ns> -p <pod> --failed --paths --timeout 15 -o json \
  | jq -r 'select(.fname | test("ld\\.so\\.cache|glibc-hwcaps|lib.*\\.so") | not)
           | "\(.fname)\t\(.error)"'
```

Read: `fname` is the exact path the process tried; `error` is the errno
(`ENOENT` = wrong path / missing mount; `EACCES` = perms → pivot to
`trace_capabilities`). `--paths` populates path fields. This catches the classic
"app reads /etc/config/foo but the ConfigMap mounted it at /config/foo" bug that
never appears in app logs.

**Three live-verified gotchas when hunting a missing file:**
- **Filter the glibc loader noise.** On any glibc image `--failed` floods with
  benign `ENOENT`s (`ld.so.cache`, `glibc-hwcaps/*`, `libm.so.6` fallbacks) — the
  dynamic loader probing standard paths. `--failed` alone is not enough; the `jq`
  `select(… | not)` above drops that noise so the real app-config miss stands out.
- **`fname` is reliable on failures; `fpath` is not.** On a *failed* open the kernel
  never resolves the dentry, so `fpath` comes back **empty** — only `fname` (the raw
  path argument) is populated. Read `fname` when hunting a missing file; trust
  `fpath` only on *successful* opens.
- **Never write `-o columns=field,field` — it silently emits ZERO rows.** `-o`
  parses its value as a comma-separated list of output *modes*, so
  `-o columns=comm,error` becomes the modes `columns=comm`, `error` — both unknown
  (`output mode "error" … not supported; skipping data source`) and nothing prints.
  Use **`-o columns --fields comm,error`** to pick columns (verified live, ig v0.54),
  or `-o json` for any read that includes the errno.

## Slow disk / file I/O

- **`trace_fsslower`** — open/read/write/fsync operations **slower than a
  threshold**. Verified flags: **`--min <µs>`** (latency floor — set it so only
  outliers show), **`--filesystem <fs>`** (btrfs/ext4/fuse/nfs/…; scope to the FS
  you care about). Use to prove "storage is slow" and see which op/file.
- **`profile_blockio`** — histogram of **block-device I/O latency** (the layer
  below the FS). Use to localize slowness to the device vs the filesystem.
  Verified flags: **`-t`/`--timeout`** — it's a histogram gadget: it accumulates
  while running and **emits the histogram when `--timeout` expires**, so always set
  one; plus `--sort` and `--max-entries` (`-1` = unlimited). It has **no**
  `--interval`/`--count` — the histogram is bounded by `--timeout`, not an interval.
- **`top_blockio`** — live per-device block I/O ranking — "which device/container
  is doing the I/O". Verified flags: **`--sort`** (join fields with `,`; prefix a
  field with `-` for descending, e.g. `--sort -bytes`) and `--max-entries`.

```bash
# File ops slower than 10ms on ext4 in this namespace
kubectl gadget run trace_fsslower:latest -n <ns> --filesystem ext4 --min 10000 --timeout 20 -o json
```

Disambiguate: **`trace_fsslower`** = per-operation FS latency outliers (which
file/op is slow); **`profile_blockio`** = block-device latency *histogram* (is the
disk itself slow); **`top_blockio`** = live per-device/container I/O *ranking*
(who is doing the I/O). FS-slow but device-fast ⇒ look above the block layer.

## Mounts, links, fd passing, notifications

- **`trace_mount`** — `mount`/`umount` syscalls (volume/mount debugging, esp. in
  init containers or CSI).
- **`trace_link`** — hardlink/symlink creation (surprising symlink resolution).
- **`fdpass`** — file descriptors passed over unix sockets (SCM_RIGHTS) — niche,
  for privilege/fd-leak analysis between processes.
- **`fsnotify`** — inotify/fanotify events: "who is watching this path" (config
  reloaders, watchers eating inotify limits). Two event families share one stream
  — **inotify** rows carry `i_*` fields (`i_wd` watch descriptor, `i_mask` event
  mask, `i_ino` inode) and **fanotify** rows carry `fa_*` fields; the `type`
  column tells them apart. Group by `i_wd` to find the busy watch, or by `i_mask`
  for the dominant event class:

```bash
# Which inotify watch is the busiest? (group by watch descriptor)
kubectl gadget run fsnotify:latest -n <ns> --timeout 15 -o json \
  | jq -r 'select(.type=="inotify") | .i_wd' | sort | uniq -c | sort -rn
```

## Notes

- `trace_open`/`trace_fsslower`/`trace_mount` are streaming — bound `--timeout`.
- `snapshot_file` is one-shot but can **block waiting on node/DaemonSet
  responses** — pair it with **`--timeout`** (not just `--max-entries`/`--sort`),
  or a run can hang indefinitely.
- Always prefer `--failed`/`--min` to shrink output to the events that matter —
  full FS traces are extremely high-volume and will flood the agent's context.
