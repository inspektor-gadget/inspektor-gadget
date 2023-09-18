---
title: 'Using top file'
weight: 20
description: >
  Periodically report read/write activity by file.
---

The top file gadget is used to visualize reads and writes by file, with container details.

### On Kubernetes

This guide will deploy an example workload that performs some disk I/O
activity to show how to use `top file`.

Before starting our workload, let's start our top file gadget to be sure it captures
all the events from the beginning:

```bash
$ kubectl gadget top file -p mypod
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
...
```

The `T` column indicates the type of the file: `R` for regular files, `S` for
sockets, and `O` for other (including pipes). By default only regular files are
shown; use the `-a` option to show all file types.

In another terminal, let's create our pod. It'll install `git` and then
clone the linux source code.

```
$ kubectl run -it mypod --image ubuntu -- /bin/sh -c "apt-get update && apt-get install -y git && git clone https://github.com/torvalds/linux"
```

We can see how the `top file` terminal shows the files that are read and
written by the pod. For instace, apt-get is reading a lot of files in
when updating the packages list and installing packages.

```bash
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          425    0      27022   0       R archive.ubuntu.com_ubuntu_dists_focal-updates_main_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          278    0      17775   0       R archive.ubuntu.com_ubuntu_dists_focal_main_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          244    0      15594   0       R security.ubuntu.com_ubuntu_dists_focal-security_main_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          93     0      5921    0       R archive.ubuntu.com_ubuntu_dists_focal_universe_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          91     0      5797    0       R archive.ubuntu.com_ubuntu_dists_focal-updates_universe_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          82     0      5160    0       R archive.ubuntu.com_ubuntu_dists_focal-updates_restricted_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          73     0      4568    0       R security.ubuntu.com_ubuntu_dists_focal-security_restricted_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          70     0      4435    0       R security.ubuntu.com_ubuntu_dists_focal-security_universe_binary-amd64_Packages.lz4
ubuntu-hirsute   default          mypod            mypod            642727  apt-get          19     0      1172    0       R archive.ubuntu.com_ubuntu_dists_focal_multiverse_binary-amd64_Packages.lz4
```

After the initial installation is done, we can see how git uses a
temporary file to store the repository being cloned.

```
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
ubuntu-hirsute   default          mypod            mypod            647042  git              0      1070   0       4280    R tmp_pack_2rpZd
```

Finally, we need to clean up our pod, press Ctrl + C on its terminal and
them remove it:

```bash
$ kubectl delete pod mypod
```

By default the top file gadget prints a summary each second. It accepts a numeric argument to indicate the interval to use:

```bash
$ kubectl gadget top file 5 # will print a summary each 5 seconds
```

This gadget also supports the following flags to customize the output:

```bash
$ kubectl gadget top file --help
Trace reads and writes by file

Usage:
  kubectl-gadget top file [interval] [flags]

Flags:
  -a, --all-files              Include non-regular file types (sockets, FIFOs, etc)
...
  -r, --maxrows int            Maximum rows to print (default 20)
...
```

### With `ig`

Start a container that performs some write operations to a file:

```bash
$ docker run --rm --name test-top-file busybox /bin/sh -c 'while true; do echo foo > bar; sleep 1; done'
```

Start the gadget and it'll show those operations:

```bash
$ sudo ig top file -c test-top-file
RUNTIME.CONTAINERNAME                  PID        COMM             READS                WRITES               RBYTES               WBYTES               T FILE
test-top-file                          139255     sh               0                    1                    0B                   4B                   R bar
```
