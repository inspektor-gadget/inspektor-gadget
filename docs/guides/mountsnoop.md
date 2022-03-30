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
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
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

```bash
NODE             NAMESPACE        POD              CONTAINER        COMM             PID     TID     MNT_NS      CALL
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext3", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext2", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "ext4", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "vfat", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "msdos", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "iso9660", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "fuseblk", MS_SILENT, "") = -2
minikube         default          busybox-0        busybox-0        mount            14469   14469   4026532682  mount("/foo", "/bar", "xfs", MS_SILENT, "") = -2
```

## Use JSON output.

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget mountsnoop -o json
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":7954,"fs":"ext3","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":4051,"fs":"ext2","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":3702,"fs":"ext4","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":11737,"fs":"vfat","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":4145,"fs":"msdos","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":10073,"fs":"iso9660","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":4232,"fs":"fuseblk","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
{"type":"normal","node":"minikube","namespace":"default","pod":"busybox-0","container":"busybox-0","mntnsid":4026532588,"pid":5307,"tid":5307,"comm":"mount","operation":"mount","ret":-2,"latency":3586,"fs":"xfs","source":"/mnt","target":"/mnt","flags":["MS_SILENT"]}
# You can use jq to make the output easier to read:
$ kubectl gadget mountsnoop -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "default",
  "pod": "busybox-0",
  "container": "busybox-0",
  "mntnsid": 4026532588,
  "pid": 5307,
  "tid": 5307,
  "comm": "mount",
  "operation": "mount",
  "ret": -2,
  "latency": 7954,
  "fs": "ext3",
  "source": "/mnt",
  "target": "/mnt",
  "flags": [
    "MS_SILENT"
  ]
}
{
  "type": "normal",
  "node": "minikube",
  "namespace": "default",
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
