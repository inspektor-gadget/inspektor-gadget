---
title: 'Using `top block-io`'
weight: 10
---

The `top block-io` gadget is used to trace block devices I/O.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top block-io
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             R/W MAJOR  MINOR  BYTES   TIME(µs) IOs
```

Indeed, it is waiting for I/O to occur.
So, open *another terminal* and keep and eye on the first one, `exec` the container and use `dd`:

```bash
$ kubectl exec -ti test-pod -- dd if=/dev/zero of=/tmp/foo count=16384
```

On *the first terminal*, you should see:

```
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             R/W MAJOR  MINOR  BYTES   TIME(µs) IOs
minikube         default          test-pod         test-pod         7767    dd               W   0      0      1564672 3046     4
```

This line correspond to the block device I/O initiated by `dd`.

## Only print some information

You can customize the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command of the process which sent a signal:

```bash
$ kubectl gadget top block-io -o custom-columns=pid,comm
PID     COMM
7767    dd
```

The following command is the same as default printing:

```bash
$ kubectl gadget top block-io -o custom-columns=node,namespace,pod,container,pid,comm,r/w,major,minor,bytes,time,ios
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             R/W MAJOR  MINOR  BYTES   TIME(µs) IOs
minikube         default          test-pod         test-pod         7767    dd               W   0      0      1564672 3046     4
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget top block-io -o json
[]
[{"node":"minikube","namespace":"default","pod":"test-pod","container":"test-pod","write":true,"bytes":2625536,"us":7075,"io":7,"mountnsid":4026532579,"pid":10310,"comm":"dd"}]
[]
# You can use jq to make the output easier to read:
$ kubectl gadget top block-io -o json | jq
[]
[
  {
    "node": "minikube",
    "namespace": "default",
    "pod": "test-pod",
    "container": "test-pod",
    "write": true,
    "bytes": 2625536,
    "us": 7075,
    "io": 7,
    "mountnsid": 4026532579,
    "pid": 10310,
    "comm": "dd"
  }
]
[]
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```

