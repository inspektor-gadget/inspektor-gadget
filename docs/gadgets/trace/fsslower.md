---
title: 'Using trace fsslower'
weight: 20
description: >
  Trace open, read, write and fsync operations slower than a threshold.
---

![Screencast of the trace fsslower gadget](fsslower.gif)

The trace fsslower gadget streams file operations (open, read, write and
fsync) that are slower than a threshold.

### On Kubernetes

In this guide you'll deploy an example workload that performs some
open(), read() write() and sync() calls and will trace which ones are
slower than 1 ms.

Let's start the gadget before running our workload:

```bash
$ kubectl gadget trace fsslower -f ext4 -m 1 -p mypod
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             T BYTES  OFFSET  LAT      FILE
```

With `-f` we're indicating the type of filesystem we want to trace,
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
$ kubectl gadget trace fsslower -f ext4 -m 1 -p mypod
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             T BYTES  OFFSET  LAT      FILE
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

### With `ig`

Let's start the gadget in a terminal:

```bash
$ sudo ig trace fsslower -f ext4 -m 1 -c test-trace-fsslower
RUNTIME.CONTAINERNAME          PID              COMM             T      BYTES     OFFSET        LAT FILE
```

Launch a container that will perform input/output operations:

```bash
$ docker run --name test-trace-fsslower -it --rm debian /bin/sh -c "apt-get update && apt-get install -y git"
Get:1 http://deb.debian.org/debian bullseye InRelease [116 kB]
Get:2 http://deb.debian.org/debian-security bullseye-security InRelease [48.4 kB]
...
0 added, 0 removed; done.
Running hooks in /etc/ca-certificates/update.d...
done.
```

The tool will list the I/O operations that were slower than 1ms:

```bash
$ sudo ig trace fsslower -f ext4 -m 1 -c test-trace-fsslower
RUNTIME.CONTAINERNAME          PID              COMM             T      BYTES     OFFSET        LAT FILE
test-trace-fsslower            35065            apt-get          R      32771          0       7671 status
test-trace-fsslower            35303            apt-get          R       5619          0       7434 extended_states
test-trace-fsslower            35312            dpkg-preconfigu  F 922337203…          0       3586 #29920952
test-trace-fsslower            35312            dpkg-preconfigu  F 922337203…          0       4239 #29920954
test-trace-fsslower            35315            dpkg             F 922337203…          0       3774 control
test-trace-fsslower            35315            dpkg             F 922337203…          0       3049 md5sums
test-trace-fsslower            35315            dpkg             F 922337203…          0       3064 tmp.ci
test-trace-fsslower            35315            dpkg             F 922337203…          0       2886 tmp.i
test-trace-fsslower            35315            dpkg             F 922337203…          0       4173 updates
...
```
