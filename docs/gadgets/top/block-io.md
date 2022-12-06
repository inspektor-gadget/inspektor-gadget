---
title: 'Using top block-io'
weight: 20
description: >
  Periodically report block device I/O activity.
---

The top block-io gadget is used to visualize the containers generating
the most block device input/output.

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

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```
