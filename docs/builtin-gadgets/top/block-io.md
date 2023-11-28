---
title: 'Using top block-io'
weight: 20
description: >
  Periodically report block device I/O activity.
---

The top block-io gadget is used to visualize the containers generating
the most block device input/output.

### On Kubernetes

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top block-io
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             R/W MAJOR  MINOR  BYTES   TIME(µs) IOs
```

Indeed, it is waiting for I/O to occur.
So, open *another terminal* and keep and eye on the first one, `exec` the container and use `dd`:

```bash
$ kubectl exec -ti test-pod -- dd if=/dev/zero of=/tmp/foo count=16384
```

On *the first terminal*, you should see:

```
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             R/W MAJOR  MINOR  BYTES   TIME(µs) IOs
minikube         default          test-pod         test-pod         7767    dd               W   0      0      1564672 3046     4
```

This line correspond to the block device I/O initiated by `dd`.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```

### With `ig`

Start a container that performs some IO activity:

```bash
$ docker run --rm --name test-top-block-io busybox /bin/sh -c'while true; do dd if=/dev/zero of=/tmp/foo count=4096; sync; done'
```

Start the gadget on another terminal and you'll see the activity produced by the `test-top-block-io` container.

```bash
$ sudo ig top block-io -c test-top-block-io
RUNTIME.CONTAINERNAME                   PID         COMM                  R/W MAJOR                MINOR                BYTES                TIME                 OPS
test-top-block-io                       63666       sync                  W   253                  0                    24576                428                  5
test-top-block-io                       63715       dd                    W   253                  0                    2097152              4816                 5
...
```