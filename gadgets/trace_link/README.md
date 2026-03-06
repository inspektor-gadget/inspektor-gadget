# trace_link

The `trace_link` gadget emits events when links are created:

- hard links (`security_path_link`)
- symlinks (`security_path_symlink`)

Each event includes:

- `is_symlink`: `false` for hard links, `true` for symlinks
- `target`: hardlink source path, or symlink raw target string
- `linkpath`: path of the link being created

Quick start:

```bash
sudo ig run trace_link
```

Notes:

- For symlinks, `target` is the raw target string as passed by userspace.
- The full guide and examples are in the docs link below.

Check the full documentation on https://inspektor-gadget.io/docs/latest/gadgets/trace_link
