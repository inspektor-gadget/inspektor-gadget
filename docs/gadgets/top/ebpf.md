---
title: 'Using top ebpf'
weight: 20
description: >
  Periodically report ebpf runtime stats.
---

The top ebpf gadget is used to visualize the usage and performance of eBPF programs.

### On Kubernetes

This guide will let you run another gadget (we're using `top file` in this example) and see its metrics
using `top ebpf`.

So first, start `top ebpf` in a terminal. You should see something like:

```bash
$ kubectl gadget top ebpf
K8S.NODE         PROGID   TYPE             NAME             PID     COMM                      RUNTIME   RUNCOUNT      MAPMEMORY MAPCOUNT
minikube         503      Tracing          ig_top_ebpf_it   573222  gadgettracerman           54.09µs       1069            12B        1
minikube         187      CGroupDevice                                                        2.292µs          1             0B        0
minikube         13       CGroupSKB                                                                0s          0             0B        0
...
```

The output should already contain the `top ebpf` gadget itself.

Now, in a second terminal, start `top file` on the _gadget_ namespace to get some output.

```bash
$ kubectl gadget top file -n gadget
K8S.NODE         K8S.NAMESPACE    K8S.POD                        K8S.CONTAINER    PID     COMM             READS  WRITES R_KB    W_KB    T FILE
minikube         gadget           gadget-k2mvp                   gadget           575955  runc:[2:INIT]    1      0      0       0       R cap_last_cap
minikube         gadget           gadget-k2mvp                   gadget           575955  runc:[2:INIT]    2      0      8       0       R group
minikube         gadget           gadget-k2mvp                   gadget           575955  gadgettracerman  2      0      8       0       R UTC
...
```

While the `top file` gadget is still running, go back to the first terminal.
Some eBPF programs of type `Kprobe` should pop up, including their runtime and run count in the current interval
(default is 1s):

```bash
$ kubectl gadget top ebpf
K8S.NODE         PROGID   TYPE             NAME             PID     COMM                      RUNTIME   RUNCOUNT      MAPMEMORY MAPCOUNT
minikube         506      Kprobe           ig_topfile_rd_e  573222  gadgettracerman         824.589µs       2076       40.95MiB        4
minikube         505      Tracing          ig_top_ebpf_it   573222  gadgettracerman          47.171µs       1103            12B        1
minikube         507      Kprobe           ig_topfile_wr_e  573222  gadgettracerman         609.645µs        836       40.95MiB        4
minikube         187      CGroupDevice                                                        4.417µs          2             0B        0
minikube         13       CGroupSKB                                                                0s          0             0B        0
minikube         8        CGroupSKB                                                                0s          0             0B        0
...
```

So in this case for example, in the past second `vfs_write_entry` has been called 647 times, which took 614.455µs.
The program references 4 maps that have a total maximum size of 40.953 MB (see below for more information on MapMemory).

If you want to get the cumulative runtime and run count of the eBPF programs starting from the beginning of the trace,
you can call the gadget with the custom-columns option and specify the cumulruntime and cumulruncount columns.
Combined with the `--sort cumulruntime` and `--timeout 60` parameters, you can for example measure the time spent
over a minute:

```bash
$ kubectl-gadget top ebpf -o columns=k8s.node,progid,type,name,pid,comm,cumulruntime,cumulruncount --sort cumulruntime --timeout 60
K8S.NODE         PROGID   TYPE             NAME             PID     COMM                 CUMULRUNTIME CUMULRUNCOUNT
minikube         509      Tracing          ig_top_ebpf_it   573222  gadgettracerman        1.265693ms         15879
minikube         187      CGroupDevice                                                       40.795µs            48
minikube         256      CGroupDevice                                                        5.834µs             2
minikube         13       CGroupSKB                                                                0s             0
minikube         7        CGroupSKB                                                                0s             0
minikube         8        CGroupSKB                                                                0s             0
...
```

### With `ig`

Run any tool that uses eBPF, for instance, [iovisor/bcc `execsnoop`](https://github.com/iovisor/bcc/blob/v0.26.0/libbpf-tools/execsnoop.bpf.c): from BCC. Please note that it can be run on the host directly.


```bash
$ sudo ./execsnoop
PCOMM            PID    PPID   RET ARGS
runc             167851 142428   0 /usr/bin/runc --version
docker-init      167857 142428   0 /usr/bin/docker-init --version
...
```

Start the `top ebpf` gadget in another terminal. It'll show the programs installed by the tool above.

```bash
$ sudo ig top ebpf
PROGID     TYPE                      NAME                     PID                      COMM                          RUNTIME RUNCOUNT                   MAPMEMORY MAPCOUNT
1102       Tracing                   ig_top_ebpf_it           167925                   ig                          299.054µs 5534                            4KiB 1
1097       TracePoint                tracepoint__sys          167850                   execsnoop                    25.055µs 2                           75.48MiB 3
1099       TracePoint                tracepoint__sys          167850                   execsnoop                    23.629µs 2                           75.48MiB 4
```

### A note about memory usage of maps

The shown value for MapMemory is read from `/proc/<pid>/fdinfo/<map_id>`.
This is the maximum size the map can have, but it doesn't necessarily reflect its current memory allocation. Additionally, maps can
be used by more than one program and would account towards the MapMemory of all those programs.

Also note:
* BPF_MAP_TYPE_PERF_EVENT_ARRAY: value_size is not counting the ring buffers, but only their file descriptors (i.e. sizeof(int) = 4 bytes)
* BPF_MAP_TYPE_{HASH,ARRAY}_OF_MAPS: value_size is not counting the inner maps, but only their file descriptors (i.e. sizeof(int) = 4 bytes)

### A note about CPU usage

There are two types of cpu usage metrics available in top ebpf gadget:
* TotalCPUUsage: It means all ebpf progs' share of the elapsed CPU time since the last update, expressed as a percentage of total CPU time. This value can be >100% because it summed up cpu time in all cpu cores, similar to linux `top`.
* PerCPUUsage: This value is `TotalCPUUsage / CPUCores` and `CPUCores` is the number of cpu cores in a node. PerCPUUsage will be always be <=100%. When using ebpf top gadget to check cpu usage for many nodes, it's suggested to use PerCPUUsage.

To show them, you can run the gadget with `percpu` and `totalcpu` specified in `-o columns` option.
