---
title: 'Using top ebpf'
weight: 20
description: >
  Periodically report ebpf runtime stats.
---

The top ebpf gadget is used to visualize the usage and performance of eBPF programs. 

This guide will let you run another gadget (we're using `top file` in this example) and see its metrics
using `top ebpf`.

So first, start `top ebpf` in a terminal. You should see something like:

```bash
$ kubectl gadget top ebpf
NODE             PROGID   TYPE             NAME             PID     COMM                      RUNTIME   RUNCOUNT
minikube         6344     Tracing          gadget_ebpftop   540621  gadgettracerman          86.911µs       1071
minikube         62       CGroupDevice                      2378    systemd                        0s          0
minikube         48       CGroupSKB                         2378    systemd                        0s          0
...
```

The output should already contain the `top ebpf` gadget itself.

Now, in a second terminal, start `top file` on the _gadget_ namespace to get some output.

```bash
$ kubectl gadget top file -n gadget
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             READS  WRITES R_Kb    W_Kb    T FILE
minikube         gadget           gadget-9fnsx     gadget           1272964 runc:[2:INIT]    2      0      0       0       R filesystems
minikube         gadget           gadget-9fnsx     gadget           1272964 sh               2      0      1       0       R libc-2.31.so
minikube         gadget           gadget-9fnsx     gadget           540621  gadgettracerman  3      0      1       0       R cmdline
...
```

While the `top file` gadget is still running, go back to the first terminal.
Some eBPF programs of type `Kprobe` should pop up, including their runtime and run count in the current interval
(default is 1s):

```bash
$ kubectl gadget top ebpf
NODE             PROGID   TYPE             NAME             PID     COMM                      RUNTIME   RUNCOUNT
minikube         6346     Kprobe           vfs_write_entry  540621  gadgettracerman        3.948619ms        378
minikube         6345     Kprobe           vfs_read_entry   540621  gadgettracerman         677.012µs       1157
minikube         6347     Tracing          gadget_ebpftop   540621  gadgettracerman          65.069µs       1101
minikube         26       CGroupDevice                                                        3.667µs          2
minikube         62       CGroupDevice                      2378    systemd                        0s          0
minikube         53       CGroupDevice                                                             0s          0
...
```

So in this case for example, in the past second `vfs_write_entry` has been called 378 times, which took 3.948619ms.

If you want to get the cumulative runtime and run count of the eBPF programs starting from the beginning of the trace,
you can call the gadget with the custom-columns option and specify the cumulruntime and cumulruncount columns.
Combined with the `--sort cumulruntime` and `--timeout 60` parameters, you can for example measure the time spent
over a minute:

```bash
$ kubectl-gadget top ebpf -o custom-columns=node,progid,type,name,pid,comm,cumulruntime,cumulruncount --sort cumulruntime --timeout 60
NODE             PROGID   TYPE             NAME             PID     COMM                 CUMULRUNTIME CUMULRUNCOUNT
minikube         2598     Tracing          gadget_ebpftop   2215151 gadgettracerman        5.239255ms         61443
minikube         24       CGroupDevice                                                      147.327µs           224
minikube         85       CGroupDevice                                                       12.209µs             4
minikube         60       CGroupDevice                      1765    systemd                        0s             0
minikube         48       CGroupDevice                      1765    systemd                        0s             0
...
```
