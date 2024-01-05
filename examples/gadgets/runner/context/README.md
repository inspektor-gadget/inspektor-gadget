# Runner example

This is a basic example showing how to use the
[pkg/runner](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/runner/)
package to run any image based gadgets directly from your program

In this case we use the [official trace_open gadget](ghcr.io/inspektor-gadget/gadget/trace_open:latest) to check if `/etc/passwd` is accessed by someone.
The information is then printed and we stop gadget through canceling the context

## How to build

```bash
$ go build .
```

## How to run

```bash
sudo ./context
{"runtime": {"runtimeName": "", "containerId": "", "containerName": "", "containerImageName": "", "containerImageDigest": ""}, "k8s": {"node": "", "namespace": "", "pod": "", "container": "", "hostnetwork": false}, "timestamp": "2024-01-08T18:12:35.509857394+01:00", "pid": 68186, "uid": 1000, "gid": 1000, "mntns_id": 4026531841, "ret": 3, "flags": 524288, "mode": 0, "comm": "passwd", "fname": "/etc/passwd"}
```
