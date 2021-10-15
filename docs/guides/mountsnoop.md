---
title: 'The "mountsnoop" gadget'
weight: 10
---

The `mountsnoop` gadget is used to monitor `mount` and `umount` syscalls.
In this guide, we will learn how to use it by running a small `kubernetes` cluster inside `minikube`.

## How to use it?

First, we need to create two pods for us to play with:
```bash
$ kubectl run busybox-0 --image busybox:latest sleep inf
$ kubectl run busybox-1 --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:
```bash
$ kubectl gadget mountsnoop
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
```

Indeed, it is waiting for `mount` and `umount` to be called.
So, in *an other terminal*, `exec` a container and try to `mount` something:
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
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext3", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext2", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "ext4", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "vfat", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "msdos", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "iso9660", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "fuseblk", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            12841   12841   4026532682  mount("/mnt", "/mnt", "xfs", MS_SILENT, "") = -ENOENT
```

All these lines correspond to the error we get from `mount` inside the pod.

## Restrain output to certain pods

It can be useful to restrain the output to certains pods.
For this, you can use `--selector` option.
In a first terminal, run the following:
```bash
$ kubectl get pods --show-labels
NAME        READY   STATUS    RESTARTS   AGE     LABELS
busybox-0   1/1     Running   0          2m9s    run=busybox-0
busybox-1   1/1     Running   0          3m59s   run=busybox-1
$ kubectl gadget mountsnoop --selector run=busybox-0
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
```

As you can see, the `--selector` option, and its `-l` shorthand awaits for pods labels as argument.
In an *other terminal*, run these commands:
```bash
# Exec the first pod:
$ kubectl exec -ti busybox-0 -- mount /foo /bar
mount: mounting /foo on /bar failed: No such file or directory
command terminated with exit code 255
# Exec the other one:
$ kubectl exec -ti busybox-1 -- mount /quux /quuz
mount: mounting /quux on /quuz failed: No such file or directory
command terminated with exit code 255
```

Go back to the first terminal, you should only output related to `mount /foo /bar` as a result of using `--selector` options filtering the pods:
```
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext3", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext2", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext4", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "vfat", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "msdos", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "iso9660", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "fuseblk", MS_SILENT, "") = -ENOENT
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "xfs", MS_SILENT, "") = -ENOENT
```

## Use JSON output.

This gadget supports JSON output, for this simply use `-o json`:
```bash
$ kubectl gadget mountsnoop -o json
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "ext3"}
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "ext2"}
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "ext4"}
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "vfat"}
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "msdos"}
{"node": "minikube", "pcomm": "runc", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 15197, "type": "iso9660"}
{"node": "minikube", "pcomm": "containerd-shim", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 11312, "type": "fuseblk"}
{"node": "minikube", "pcomm": "containerd-shim", "pid": 15207, "comm": "mount", "pod": "busybox-1", "data": "", "mnt_ns": 4026532573, "container": "busybox-1", "target": "/quuz", "tgid": 15207, "namespace": "default", "source": "/quux", "flags": 32768, "mntnsid": 0, "ppid": 11312, "type": "xfs"}
# You can use jq to make the output easier to read:
$ kubectl gadget mountsnoop -o json | jq
{
  "node": "minikube",
  "pcomm": "runc",
  "pid": 15681,
  "comm": "mount",
  "pod": "busybox-1",
  "data": "",
  "mnt_ns": 4026532573,
  "container": "busybox-1",
  "target": "/quuz",
  "tgid": 15681,
  "namespace": "default",
  "source": "/quux",
  "flags": 32768,
  "mntnsid": 0,
  "ppid": 15670,
  "type": "ext3"
}
{
  "node": "minikube",
  "pcomm": "runc",
  "pid": 15681,
  "comm": "mount",
  ...
}
...
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the two pods we created:
```bash
$ kubectl delete pod busybox-0 busybox-1
pod "busybox-0" deleted
pod "busybox-1" deleted
```
