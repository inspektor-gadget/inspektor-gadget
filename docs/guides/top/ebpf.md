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

If you want to get the total runtime and total run count of the eBPF programs, you can call the gadget with the custom
columns option:

```bash
$ kubectl-gadget top ebpf -o custom-columns=node,progid,type,name,runtime,runcount,totalruncount,totalruntime --sort totalruntime
NODE             PROGID   TYPE             NAME                  RUNTIME   RUNCOUNT  T-RUNCOUNT    T-RUNTIME
minikube         26       CGroupDevice                                0s          0        3817   2.692936ms
minikube         6394     TracePoint       tgkill_entry        105.209µs         17         584   2.442174ms
minikube         6395     TracePoint       tgkill_exit          60.625µs         17         584   1.166054ms
minikube         6393     TracePoint       sig_trace            38.085µs         17         653     996.16µs
minikube         6400     Tracing          gadget_ebpftop       37.202µs       1125        3345    258.998µs
minikube         103      CGroupDevice                                0s          0         101    151.455µs
minikube         6068     CGroupDevice                                0s          0          22      9.542µs
...
```

Please keep in mind that collection of the runtime stats is disabled by default for performance reasons and will only
be enabled by the `top ebpf` gadget for the time it is running. That means that the "total" runtime and run count
reflect only the time in which `top ebpf` was running.
