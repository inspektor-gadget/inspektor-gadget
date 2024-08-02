# snapshot process

Show running processes

## Getting started
Pulling the gadget:
```
sudo ig image pull ghcr.io/inspektor-gadget/gadget/snapshot_process:latest
```
Running the gadget:
```
sudo ig run ghcr.io/inspektor-gadget/gadget/snapshot_process:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/snapshot_process:latest [flags]
```

## Flags

### `--threads`
Show all threads (by default, only processes are shown)

Default value: "false"
