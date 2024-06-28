# trace malloc

use uprobe to trace malloc and free in libc.so

## Getting started
Pulling the gadget:
```
sudo IG_EXPERIMENTAL=true ig image pull ghcr.io/inspektor-gadget/gadget/trace_malloc:latest
```
Running the gadget:
```
sudo IG_EXPERIMENTAL=true ig run ghcr.io/inspektor-gadget/gadget/trace_malloc:latest [flags]
kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_malloc:latest [flags]
```

## Flags
No flags.