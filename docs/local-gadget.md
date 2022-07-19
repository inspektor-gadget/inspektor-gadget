---
title: local-gadget
weight: 80
description: >
  How to use the local-gadget tool.
---

Inspektor Gadget can also be used without Kubernetes to trace containers with
the `local-gadget` tool.

Currently, the `local-gadget` can trace containers managed by Docker regardless
of whether they were created via Kubernetes or not. In addition, it will also
use the CRI to trace containers managed by containerd and CRI-O, meaning only
the ones created via Kubernetes. Support for non-Kubernetes containers with
containerd is coming, see issue
[#734](https://github.com/kinvolk/inspektor-gadget/issues/734).

By default, the `local-gadget` will try to communicate with the Docker Engine
API and the CRI API of containerd and CRI-O:

```bash
$ docker run -d --name myContainer nginx:1.21
95b814bb82b9e30dd935b03d04a7b00b6978ce018a6f55d6a9c7a824b31ec6b5

$ sudo local-gadget list-containers
WARN[0000] Runtime enricher (cri-o): couldn't get current containers
RUNTIME       ID               NAME
containerd    7766d32caded4    calico-kube-controllers
containerd    2e3e4968b456f    calico-node
containerd    d3be7741b94ff    coredns
containerd    e7be3e4dc1bb4    coredns
containerd    fb4fe41921f30    etcd
containerd    136e7944d2077    kube-apiserver
containerd    ad8709a2c2ded    kube-controller-manager
containerd    66cf05654a47f    kube-proxy
containerd    a68bed42aa6b2    kube-scheduler
docker        95b814bb82b9e    myContainer
```

This output shows the containers `local-gadget` retrieved from Docker and
containerd, while the warning message tells us that `local-gadget` tried to
communicate with CRI-O but couldn't. In this case, it was because CRI-O was not
running in the system where we executed the test. However, it could also happen
if `local-gadget` uses a different UNIX socket path to communicate with the
runtimes. To check which paths `local-gadget` is using, you can use the `--help`
flag:

```bash
$ sudo local-gadget list-containers --help
List all containers

Usage:
  local-gadget list-containers [flags]

Flags:
  ...
      --containerd-socketpath string   containerd CRI Unix socket path (default "/run/containerd/containerd.sock")
      --crio-socketpath string         CRI-O CRI Unix socket path (default "/run/crio/crio.sock")
      --docker-socketpath string       Docker Engine API Unix socket path (default "/run/docker.sock")
  -r, --runtimes string                Container runtimes to be used separated by comma. Supported values are: docker, containerd, cri-o (default "docker,containerd,cri-o")
  ...
```

If needed, we can also specify the runtimes to be used and their UNIX socket
path:

```bash
$ sudo local-gadget list-containers --runtimes docker --docker-socketpath /some/path/docker.sock
RUNTIME    ID               NAME
docker     95b814bb82b9e    myContainer
```

The `list-containers` command also supports JSON format and filtering:

```bash
$ sudo local-gadget list-containers -o json --containername calico-kube-controllers
[
  {
    "ID": "1fd08f8d9fc300a3c312edc1718d31d424744ebbcf70a3ed84a8dc5402a64dc7",
    "Pid": 4670,
    "OciConfig": null,
    "Bundle": "",
    "Mntns": 4026532515,
    "Netns": 4026532368,
    "CgroupPath": "/sys/fs/cgroup/unified/system.slice/containerd.service",
    "CgroupID": 854,
    "CgroupV1": "/system.slice/containerd.service/kubepods-besteffort-pod07c58ca4_5b3e_49dd_baa3_af39fd0b5363.slice:cri-containerd:1fd08f8d9fc300a3c312edc1718d31d424744ebbcf70a3ed84a8dc5402a64dc7",
    "CgroupV2": "/system.slice/containerd.service",
    "Namespace": "default",
    "Podname": "calico-kube-controllers",
    "Name": "calico-kube-controllers",
    "Labels": null,
    "OwnerReference": null,
    "PodUID": "",
    "Runtime": "containerd"
  }
]
```

Please consider that some of the Kubernetes metadata: `Namespace`, `Podname`,
`PodUID` and `Name`, could not correspond to the actual values, issue
[#737](https://github.com/kinvolk/inspektor-gadget/issues/737) will fix this
soon. While, the Kubernetes metadata `Labels` and `OwnerReference`, and the OCI
runtime data: `OciConfig` and `Bundle`, will remain empty because such
information cannot be retrieved from the container runtime.

## Examples

We can execute the `local-gadget --help` flag to check the supported gadgets,
following some examples of usage.

### Process

```bash
$ sudo local-gadget snapshot process
CONTAINER                  COMM               PID
calico-kube-controllers    kube-controller    4791
calico-node                bird               3888
calico-node                bird6              3889
calico-node                calico-node        3731
calico-node                calico-node        3732
calico-node                calico-node        3733
calico-node                calico-node        3734
calico-node                calico-node        3735
calico-node                calico-node        3737
calico-node                runsv              3723
calico-node                runsv              3724
calico-node                runsv              3725
calico-node                runsv              3726
calico-node                runsv              3727
calico-node                runsv              3728
calico-node                runsv              3729
calico-node                runsv              3730
calico-node                runsvdir           3643
coredns                    coredns            4725
coredns                    coredns            4762
etcd                       etcd               1750
gadget                     gadgettracerman    39645
kube-apiserver             kube-apiserver     1793
kube-controller-manager    kube-controller    1788
kube-proxy                 kube-proxy         3227
kube-scheduler             kube-scheduler     1840
myContainer                nginx              34187
myContainer                nginx              34279
myContainer                nginx              34280
myContainer                nginx              34281
myContainer                nginx              34282
```

We can filter by container name:

```bash
$ sudo local-gadget snapshot process --containername gadget
CONTAINER    COMM               PID
gadget       gadgettracerman    39645
```

And, show the all threads using the `-t` flag:

```bash
$ sudo local-gadget snapshot process --containername gadget -t
CONTAINER    COMM               TGID     PID
gadget       gadgettracerman    39645    39645
gadget       gadgettracerman    39645    39668
gadget       gadgettracerman    39645    39669
gadget       gadgettracerman    39645    39670
gadget       gadgettracerman    39645    39671
gadget       gadgettracerman    39645    39672
gadget       gadgettracerman    39645    39673
gadget       gadgettracerman    39645    39674
gadget       gadgettracerman    39645    39677
gadget       gadgettracerman    39645    39678
```

Consider that the JSON format and the `custom-columns` output mode are also
supported using the `--output` flag.

## Interactive Mode

The interactive mode allows us to create multiple traces at the same time.

Use the `list-gadgets` commands to verify the supported gadgets:

```bash
$ sudo local-gadget interactive
» list-gadgets
audit-seccomp
dns
network-graph
process-collector
seccomp
snisnoop
socket-collector
```

Following are some examples of usage.

### dns

Start the DNS gadget:

```bash
$ sudo local-gadget interactive --runtimes docker
» create dns trace1 --container-selector shell01
» stream trace1 -f
{"notice":"tracer attached","node":"local","namespace":"default","pod":"shell01"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pkt_type":"OUTGOING"}
{"notice":"tracer detached","node":"local","namespace":"default","pod":"shell01"}
```

Start a container:

```bash
$ docker run -ti --rm --name shell01 busybox wget wikipedia.org
```

### seccomp

```bash
$ sudo local-gadget interactive --runtimes docker
» create seccomp trace1 --container-selector shell01 --output-mode Status
```

Start a container:

```bash
$ docker run -ti --rm --name shell01 busybox
```

Resume from the local-gadget terminal:

```bash
» operation trace1 generate
State: Started
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "arch_prctl",
        "brk",
        "close",
        "fcntl",
        "getcwd",
        "geteuid",
        "getpgrp",
        "getpid",
        "getppid",
        "getuid",
        "ioctl",
        "open",
        "poll",
        "read",
        "rt_sigaction",
        "rt_sigreturn",
        "setpgid",
        "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```
