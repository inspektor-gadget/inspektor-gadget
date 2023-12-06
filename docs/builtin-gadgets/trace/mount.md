---
title: 'Using trace mount'
weight: 20
description: >
  Trace mount and umount system calls.
---

The trace mount gadget is used to monitor `mount` and `umount` syscalls.
In this guide, we will learn how to use it by running a small Kubernetes cluster inside `minikube`.

### On Kubernetes

First, we need to create two pods for us to play with:

```bash
$ kubectl run busybox-0 --image busybox:latest sleep inf
$ kubectl run busybox-1 --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace mount
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    COMM             PID     TID     MNTNS      CALL
```

Indeed, it is waiting for `mount` and `umount` to be called.
So, in *another terminal*, `exec` a container and try to `mount` something:

```bash
$ kubectl get pods
NAME        READY   STATUS    RESTARTS   AGE
busybox-0   1/1     Running   0          13s
busybox-1   1/1     Running   0          2m3s
$ kubectl exec -ti busybox-0 -- mount /mnt /mnt
mount: mounting /mnt on /mnt failed: No such file or directory
command terminated with exit code 255
```

Go back to *the first terminal* and see:

```bash
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    COMM             PID     TID     MNTNS      CALL
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext3", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext2", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext4", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "vfat", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "msdos", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "iso9660", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "fuseblk", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "xfs", MS_SILENT, "") = -2
```

All these lines correspond to the error we get from `mount` inside the pod.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the two pods we created:

```bash
$ kubectl delete pod busybox-0 busybox-1
pod "busybox-0" deleted
pod "busybox-1" deleted
```

### With `ig`

Let's start the gadget in a terminal:

```bash
$ sudo ig trace mount -c test-trace-mount
RUNTIME.CONTAINERNAME             COMM             PID        TID        CALL
```

Run a container that uses mount:

```bash
$ docker run --name test-trace-mount -it --rm busybox /bin/sh -c "mount /bar /foo"
```

The tool will show the different mount() calls that the container performed:

```bash
$ sudo ig trace mount -c test-trace-mount
RUNTIME.CONTAINERNAME             COMM             PID        TID        CALL
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "ext3", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "ext2", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "ext4", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "squashf", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "vfat", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "fuseblk", MS_SILENT, "") = -2
test-trace-mount                  mount            235385     235385     mount("/bar", "/foo", "btrfs", MS_SILENT, "") = -2
```
