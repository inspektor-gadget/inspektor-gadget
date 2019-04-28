# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) for developers of
Kubernetes applications. While it is primarily designed for Lokomotive,
Kinvolk's open-source Kubernetes distribution, it can be used on other
Kubernetes distributions.

## How to use

```
$ inspektor-gadget
inspektor-gadget is a collection of gadgets for Kubernetes developers.

List of gadgets:
  execsnoop             Watch programs being executed in pods
  opensnoop             Watch files being opened in pods
  tcptop                Monitor the network traffic in pods
  straceback            Get strace-like logs of a pod from the past
  hints-network         Get network policy hints suited for your app
  hints-rbac            Get rbac hints suited for your app
```

Inspektor Gadget is a kubectl plugin. It can also be invoked with `kubectl gadget`.

- [Demo: the "execsnoop" gadget](Documentation/demo-execsnoop.md)
- [Demo: the "straceback" gadget](Documentation/demo-straceback.md)

## How does it work?

[architecture](Documentation/architecture.md)

## Installation (client side)

From the sources:
```
go get -u github.com/kinvolk/inspektor-gadget/cmd/inspektor-gadget
```

From the [releases](https://github.com/kinvolk/inspektor-gadget/releases).

## Requirements (server side)

- Lokomotive Edge on Flatcar Edge (preinstalled)

or

- Kubernetes
- Linux >= 4.18 (for [`bpf_get_current_cgroup_id`](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md))
- cgroup-v2 enabled in systemd, kubelet, docker, containerd and runc
- runc recompiled with [additional static OCI hooks](https://github.com/kinvolk/runc/tree/alban/static-hooks)
- tools installed on the worker nodes: [kubectl](https://kubernetes.io/docs/tasks/tools/install-kubectl/), [cgroupid](https://github.com/kinvolk/cgroupid), [bpftool](https://github.com/kinvolk/linux/tree/alban/bpftool-all/tools/bpf/bpftool)
- The gadget daemon set

