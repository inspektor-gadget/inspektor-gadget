# Runner example

This is a basic example showing how to use the
[pkg/runner](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/runner/)
package to run any image based gadgets directly from your program

In this case we use the [official trace_open gadget](ghcr.io/inspektor-gadget/gadget/trace_open:latest) to trace all open events.

## How to build

```bash
$ go build .
```

## How to run

```bash
$ sudo ./timeout
{"runtime": {"runtimeName": "", "containerId": "", "containerName": "", "containerImageName": "", "containerImageDigest": ""}, "k8s": {"node": "", "namespace": "", "pod": "", "container": "", "hostnetwork": false}, "timestamp": "2024-01-05T19:39:18.852656724+01:00", "pid": 2865636, "uid": 0, "gid": 0, "mntns_id": 4026532893, "ret": 4, "flags": 524288, "mode": 0, "comm": "runc", "fname": "/usr/bin/runc"}
{"runtime": {"runtimeName": "", "containerId": "", "containerName": "", "containerImageName": "", "containerImageDigest": ""}, "k8s": {"node": "", "namespace": "", "pod": "", "container": "", "hostnetwork": false}, "timestamp": "2024-01-05T19:39:18.853042805+01:00", "pid": 2865636, "uid": 0, "gid": 0, "mntns_id": 4026532893, "ret": 4, "flags": 524288, "mode": 0, "comm": "runc", "fname": "/proc/sys/kernel/cap_last_cap"}
{"runtime": {"runtimeName": "", "containerId": "", "containerName": "", "containerImageName": "", "containerImageDigest": ""}, "k8s": {"node": "", "namespace": "", "pod": "", "container": "", "hostnetwork": false}, "timestamp": "2024-01-05T19:39:18.853387336+01:00", "pid": 2865636, "uid": 0, "gid": 0, "mntns_id": 4026532893, "ret": -2, "flags": 524288, "mode": 0, "comm": "runc", "fname": ""}

...
```
