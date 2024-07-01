# trace capabilities

trace security capabilitiy checks

## Getting started
Pulling the gadget:
```
sudo IG_EXPERIMENTAL=true ig image pull ghcr.io/inspektor-gadget/gadget/trace_capabilities:latest
```
Running the gadget:
```
sudo IG_EXPERIMENTAL=true ig run ghcr.io/inspektor-gadget/gadget/trace_capabilities:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_capabilities:latest [flags]
```

## Flags

### `--audit_only`
Only show audit checks

Default value: "false"

### `--print-stack`
controls whether the gadget will send kernel stack to userspace

Default value: "true"

### `--unique`
Only show a capability once on the same container

Default value: "false"
