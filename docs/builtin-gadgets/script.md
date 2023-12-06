---
title: 'Using script gadget'
weight: 30
description: >
  Run bpftrace-compatible scripts using Inspektor Gadget.
---

### On Kubernetes

The script gadget allows to run [bpftrace](https://github.com/iovisor/bpftrace)-compatible scripts
on a Kubernetes cluster. To get more information about bpftrace and its features please check the
bpftrace documentation.

#### One-liners

```bash
# Files opened by process
$ kubectl gadget script -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
K8S.NODE                         OUTPUT
minikube-m02                     Attaching 1 probe...
minikube-m02                     bpftrace /sys/devices/system/cpu/online
minikube-m02                     bpftrace /sys/devices/system/cpu/online
minikube-m03                     Attaching 1 probe...
minikube-m02                     bpftrace /dev/null
minikube-m02                     bpftrace /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id
minikube-m02                     bpftrace /sys/devices/system/cpu/online
minikube-m03                     bpftrace /sys/devices/system/cpu/online
minikube-m03                     bpftrace /sys/devices/system/cpu/online
minikube-m02                     bpftrace /sys/devices/system/cpu/online
minikube                         Attaching 1 probe...
minikube-m02                     bpftrace /dev/null
minikube-m02                     bpftrace /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/id
minikube-m02                     runc /usr/bin/runc
minikube-m02                     runc /proc/sys/kernel/cap_last_cap
minikube                         runc /proc/sys/kernel/cap_last_cap
minikube-m03                     runc /proc/sys/kernel/cap_last_cap
minikube-m02                     runc
...

# Run on a single node
$ kubectl gadget script --node minikube -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'
K8S.NODE                         OUTPUT
minikube                         Attaching 1 probe...
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods/besteffort/poddc2af8ce-f414
minikube                         kubelet /proc/1645/fd
minikube                         coredns /etc/hosts
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods/besteffort/pod26b59ae5-f76b
minikube                         kubelet /proc/1565/fd
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable/podbd495b7643dfc9
minikube                         kubelet /proc/1894/fd
minikube                         kubelet /sys/fs/cgroup/devices/kubepods/besteffort
minikube                         kubelet /sys/fs/cgroup/devices/kubepods/burstable
minikube                         kubelet /sys/fs/cgroup/devices/kubepods
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods/besteffort
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods/burstable
minikube                         kubelet /sys/fs/cgroup/cpu,cpuacct/kubepods
minikube                         kubelet /sys/fs/cgroup/misc/kubepods/besteffort
minikube                         kubelet /sys/fs/cgroup/misc/kubepods/burstable
minikube                         kubelet /sys/fs/cgroup/misc/kubepods
minikube                         kubelet /sys/fs/cgroup/systemd/kubepods/besteffort
minikube                         kubelet /sys/fs/cgroup/systemd/kubepods/burstable
minikube                         kubelet /sys/fs/cgroup/systemd/kubepods
minikube                         kubelet /sys/fs/cgroup/memory/kubepods/besteffort
minikube                         kubelet /sys/fs/cgroup/memory/kubepods/burstable
minikube                         kubelet /sys/fs/cgroup/memory/kubepods
...

# Syscall count by program
$ kubectl gadget script -e 'tracepoint:raw_syscalls:sys_enter { @[comm] = count(); }'

K8S.NODE                         OUTPUT
minikube-m03                     Attaching 1 probe...
minikube-m02                     Attaching 1 probe...
minikube                         Attaching 1 probe...
^Cminikube-m02
minikube
minikube
minikube-m02
minikube-m02                     @[LIST_LEGACY]: 1
minikube-m02                     @[wpa_supplicant]: 1
minikube-m02                     @[HangWatcher]: 2
minikube-m02                     @[SharedWorker th]: 2
minikube-m02                     @[WebRTC_Worker]: 2
minikube-m03                     @[cri-dockerd]: 7345
minikube-m03                     @[EMT-0]: 8105
minikube-m03                     @[containerd-shim]: 8237
minikube-m03                     @[gadgettracerman]: 8470
minikube-m03                     @[runc]: 14030
minikube-m03                     @[EMT-7]: 15583
minikube-m03                     @[dockerd]: 22937
minikube-m03                     @[kubelet]: 27455
...
```

#### Script files

When a script does not fit on one line, it can be stored in a file and passed to the gadget using the
`-e @FILE` flag.

```bash
$ wget https://raw.githubusercontent.com/iovisor/bpftrace/master/tools/loads.bt
$ wc -l loads.bt
41 loads.bt
$ kubectl gadget script -e @./loads.bt
K8S.NODE                                         OUTPUT
minikube-docker                                  Attaching 2 probes...
minikube-docker                                  Reading load averages... Hit Ctrl-C to end.
minikube-docker                                  15:40:36 load averages: 2.960 2.451 2.166
minikube-docker                                  15:40:37 load averages: 2.960 2.451 2.166
^C
```

### Limitations

Given that `bpftrace` is executed inside the Inspektor Gadget container, it's needed to append
`/host` to the binary path in order to use uprobes.

``` bash
$ kubectl gadget script -e 'uretprobe:/host/bin/bash:readline { printf("read a line\n"); }'
```

### Future improvements

We plan to make the bpftrace and Inspektor Gadget more powerful in the future. Please check
https://github.com/inspektor-gadget/inspektor-gadget/issues/1433 issue that contains more details
about the planned features.
