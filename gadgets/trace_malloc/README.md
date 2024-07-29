# trace malloc

use uprobe to trace malloc and free in libc.so

## Getting started
Pulling the gadget:
```
sudo ig image pull ghcr.io/inspektor-gadget/gadget/trace_malloc:latest
```
Running the gadget:
```
sudo ig run ghcr.io/inspektor-gadget/gadget/trace_malloc:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_malloc:latest [flags]
```

## Flags
No flags.
