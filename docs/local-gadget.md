---
title: local-gadget
weight: 80
description: >
  Description of the local-gadget tool.
---

Inspektor Gadget relies on the Kubernetes API server to work. However, there are
[some cases](#use-cases) where it is necessary, or preferred, to trace
containers without passing through Kubernetes. In such scenarios, you can use
the `local-gadget` tool, as it allows you to collect insights from the nodes to
debug your Kubernetes containers without relying on Kubernetes itself, but on
the container runtimes. It is important to remark that `local-gadget` can also
be used to trace containers that were not created via Kubernetes.

Some characteristics of the `local-gadget`:
- It uses eBPF as its underlying core technology.
- Enriches the collected data with the Kubernetes metadata.
- Easy to install as it is a single binary (statically linked).

The architecture of `local-gadget` is described in the main
[architecture](architecture.md#local-gadget) document.

## Use cases

- In a Kubernetes environment, when the Kubernetes API server is not working
  properly, we cannot deploy Inspektor Gadget. Therefore, we still need a way to
  debug the containers of the cluster.
- In some cases, you might have root SSH access to the Kubernetes nodes of a
  cluster, but not to the `kubeconfig`.
- If you are implementing an application that needs to get insights from the
  Kubernetes node, you could include the `local-gadget` binary in your container
  image, and your app simply execs it. In such a case, it is suggested to use
  the JSON output format to ease the parsing.
- Outside a Kubernetes environment, for observing and debugging standalone
  containers.

## Installation

The instruction to install `local-gadget` are available in the main
[installation](install.md#installing-local-gadget) guide.

## Usage

Currently, the `local-gadget` can trace containers managed by Docker regardless
of whether they were created via Kubernetes or not. In addition, it can also
use the CRI to trace containers managed by containerd and CRI-O, meaning only
the ones created via Kubernetes. Support for non-Kubernetes containers with
containerd is coming, see issue
[#734](https://github.com/inspektor-gadget/inspektor-gadget/issues/734).

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
  -w, --watch                          After listing the containers, watch for new containers
  ...
```

If needed, we can also specify the runtimes to be used and their UNIX socket
path:

```bash
$ sudo local-gadget list-containers --runtimes docker --docker-socketpath /some/path/docker.sock
RUNTIME    ID               NAME
docker     95b814bb82b9e    myContainer
```

### Common features

Notice that most of the commands support the following features even if, for
simplicity, they are not demonstrated in each command guide:

- JSON format and `custom-columns` output mode are supported through the
  `--output` flag.
- It is possible to filter events by container name using the `--containername`
  flag.

For instance, for the `list-containers` command:

```bash
$ sudo local-gadget list-containers -o json --containername etcd
[
  {
    "runtime": "containerd",
    "id": "fef9c7f66e0d68c554b7ea48cc3ef4e77c553957807de7f05ad0210a05d8c215",
    "pid": 1611,
    "mntns": 4026532270,
    "netns": 4026531992,
    "cgroupPath": "/sys/fs/cgroup/unified/system.slice/containerd.service",
    "cgroupID": 854,
    "cgroupV1": "/system.slice/containerd.service/kubepods-burstable-pod87a960e902bbb19289771a77e4b07353.slice:cri-containerd:fef9c7f66e0d68c554b7ea48cc3ef4e77c553957807de7f05ad0210a05d8c215",
    "cgroupV2": "/system.slice/containerd.service",
    "namespace": "kube-system",
    "podname": "etcd-master",
    "name": "etcd",
    "podUID": "87a960e902bbb19289771a77e4b07353"
  }
]
```

## Using the interactive mode

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
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pktType":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pktType":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pktType":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pktType":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pktType":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pktType":"OUTGOING"}
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
