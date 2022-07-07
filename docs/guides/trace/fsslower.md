---
title: 'Using trace fsslower'
weight: 20
description: >
  Trace open, read, write and fsync operations slower than a threshold.
---

The trace fsslower gadget streams file operations (open, read, write and
fsync) that are slower than a threshold.

In this guide you'll deploy an example workload that performs some
open(), read() write() and sync() calls and will trace which ones are
slower than 1 ms.

Let's start the gadget before running our workload:

```bash
$ kubectl gadget trace fsslower -t ext4 -m 1 -p mypod
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             T BYTES  OFFSET  LAT      FILE
```

With `-t` we're indicating the type of filesystem we want to trace,
`ext4` in this case. The `-m` parameter indicates the threshold, in this
case operations taking more than 1ms will be printed. `-p` indicates
that we only want to trace events coming from `mypod`.

The `T` column indicates the operation type, `O` for open, `R` for read,
`W` for write and `F` for fsync.

In another terminal, let's create a pod that updates the apt-get cache
and installs git.

```bash
$ kubectl run -it mypod --image ubuntu -- /bin/sh -c "apt-get update && apt-get install -y git"
...
```

We can see how fsslower shows the operations that are taking longer than 1ms:

```bash
$ kubectl gadget trace fsslower -t ext4 -m 1 -p mypod
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             T BYTES  OFFSET  LAT      FILE
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       2.66     perl-modules-5.30.list-new
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.49     libperl5.30:amd64.list-new
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.45     control
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.01     less.list-new
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.05     symbols
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.05     md5sums
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.16     control
ubuntu-hirsute   default          mypod            mypod            579778  dpkg             F 0      0       1.09     git.list-new
ubuntu-hirsute   default          mypod            mypod            580362  dpkg             F 0      0       1.16     tmp.i
ubuntu-hirsute   default          mypod            mypod            580363  frontend         F 0      0       1.50     templates.dat-new
ubuntu-hirsute   default          mypod            mypod            582040  dpkg-trigger     F 0      0       1.10     triggers
ubuntu-hirsute   default          mypod            mypod            580382  frontend         F 0      0       1.22     templates.dat-new
ubuntu-hirsute   default          mypod            mypod            583411  dpkg             F 0      0       2.25     perl-modules-5.30.list-new
ubuntu-hirsute   default          mypod            mypod            583411  dpkg             F 0      0       2.05     libperl5.30:amd64.list-new
ubuntu-hirsute   default          mypod            mypod            583411  dpkg             F 0      0       1.13     tmp.i
ubuntu-hirsute   default          mypod            mypod            583411  dpkg             F 0      0       1.26     updates
ubuntu-hirsute   default          mypod            mypod            583411  dpkg             F 0      0       1.22     md5sums
```

That's all, let's delete our example pod

```bash
$ kubectl delete pod mypod
```
