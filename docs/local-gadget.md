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

## Running some gadgets

### Snapshot/Process

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

### Top/Block-io

```bash
$ sudo local-gadget top block-io
CONTAINER                               PID         COMM                  R/W MAJOR                MINOR                BYTES                TIME                 OPS
test-top-block-io                       63666       sync                  W   253                  0                    24576                428                  5
test-top-block-io                       63715       dd                    W   253                  0                    2097152              4816                 5
...
```

The previous output was got by running the following container

```bash
$ docker run --rm --name test-top-block-io busybox /bin/sh -c'while true; do dd if=/dev/zero of=/tmp/foo count=4096; sync; done'
```

### Top/Ebpf

```bash
$ sudo local-gadget top ebpf
PROGID     TYPE                      NAME                     PID                      COMM                          RUNTIME RUNCOUNT                   MAPMEMORY MAPCOUNT
1102       Tracing                   ig_top_ebpf_it           167925                   local-gadget                299.054µs 5534                            4KiB 1
1097       TracePoint                tracepoint__sys          167850                   execsnoop                    25.055µs 2                           75.48MiB 3
1099       TracePoint                tracepoint__sys          167850                   execsnoop                    23.629µs 2                           75.48MiB 4
```

The previous output was taken while running [iovisor/bcc `execsnoop`](https://github.com/iovisor/bcc/blob/88b5edbdc98a50dedf9a911b8f1ab5a63c574767/libbpf-tools/execsnoop.bpf.c):

```bash
$ sudo ./execsnoop
PCOMM            PID    PPID   RET ARGS
runc             167851 142428   0 /usr/bin/runc --version
docker-init      167857 142428   0 /usr/bin/docker-init --version
...
```

### Top/File

```bash
$ sudo local-gadget top file
CONTAINER                              PID        COMM             READS                WRITES               RBYTES               WBYTES               T FILE
test-top-file                          139255     sh               0                    1                    0B                   4B                   R bar
```

The above output is the result of observing the following test container:

```bash
$ docker run --rm --name test-top-file busybox /bin/sh -c 'while true; do echo foo > bar; sleep 1; done'
```

### Top/Tcp

```bash
$ sudo local-gadget top tcp
CONTAINER                                              PID         COMM             IP LOCAL                 REMOTE                SENT                 RECV
test-top-tcp                                           564780      nginx            4  127.0.0.1:80          127.0.0.1:35904       238B                 73B
test-top-tcp                                           564813      curl             4  127.0.0.1:35904       127.0.0.1:80          73B                  853B
```

This output was generated by the following test container:

```bash
$ docker run --rm --name test-top-tcp nginx /bin/sh -c 'nginx; while true; do curl localhost; sleep 1; done'
```

### Trace/Bind

```bash
$ sudo local-gadget trace bind
CONTAINER        PID     COMM             PROTO  ADDR             PORT    OPTS    IF
foo              380299  nc               TCP    ::               4242    .R...   0
```

The previous output was triggered using the following test container:

```bash
$ docker run -it --rm --name foo busybox /bin/sh -c "nc -l -p 4242"
```

In case of need, we can specify the ports we want to monitor:

```bash
$ sudo local-gadget trace bind --ports 4242
```

Use `local-gadget trace bind --help` to discover the rest of the filtering
options available for this gadget.

### Trace/Exec

This is the output when executing this gadget on a Kubernetes node:

```bash
$ sudo local-gadget trace exec
CONTAINER        PID     PPID    COMM            RET  ARGS
calico-node      416789  416777  calico-node     0    /bin/calico-node -felix-live -bird-live
calico-node      416804  416789  sv              0    /usr/local/bin/sv status /etc/service/enabled/confd
calico-node      416805  416789  sv              0    /usr/local/bin/sv status /etc/service/enabled/bird
gadget           416816  416806  gadgettracerman 0    /bin/gadgettracermanager -liveness
gadget           416842  416823  gadgettracerman 0    /bin/gadgettracermanager -liveness
calico-node      416887  416876  calico-node     0    /bin/calico-node -felix-ready -bird-ready
```

Remember that we can use the `-o custom-columns` flag to show only the columns
we are interested in:

```bash
$ sudo local-gadget trace exec -o custom-columns=container,pid,comm
CONTAINER        PID     COMM
calico-node      421023  ipset
calico-node      421039  calico-node
calico-node      421056  sv
gadget           421066  gadgettracerman
```

### Trace/Open

The trace mount tool shows the files opened by containers.

Let's start the gadget in a terminal:

```bash
$ sudo local-gadget trace open --containername test-container
CONTAINER                                                  PID        COMM             FD    ERR PATH
```

Run a container that opens some files:

```bash
$ docker run --name test-container -it --rm busybox /bin/sh -c 'while /bin/true ; do whoami ; sleep 3 ; done'
```

The tools will show the different files opened by the container:

```bash
$ sudo local-gadget trace open --containername test-container
CONTAINER                                                  PID        COMM             FD    ERR PATH
test-container                                             630417     whoami           3     0   /etc/passwd
test-container                                             630954     whoami           3     0   /etc/passwd
```


### Trace/Mount

The trace mount tool shows when a container performs a `mount()` syscall.

Let's start the gadget in a terminal:

```bash
$ sudo local-gadget trace mount
CONTAINER                         COMM             PID        TID        CALL
```

Run a container that uses mount:

```bash
$ docker run --name test-container -it --rm busybox /bin/sh -c "mount /bar /foo"
```

The tools will show the different mount() calls that the container performed:

```bash
$ sudo local-gadget trace mount
CONTAINER                         COMM             PID        TID        CALL
test-container                    mount            235385     235385     mount("/bar", "/foo", "ext3", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "ext2", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "ext4", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "squashf", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "vfat", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "fuseblk", MS_SILENT, "") = -2
test-container                    mount            235385     235385     mount("/bar", "/foo", "btrfs", MS_SILENT, "") = -2
```

### Trace/Tcp

We can also monitor the TCP connections using the tcp trace gadget. For
instance, with the following container we can see that the gadget shows that a
TCP connection was established:

```bash
$ docker run -it --rm --name test-container busybox /bin/sh -c "wget https://www.example.com"
Connecting to www.kinvolk.io (188.114.96.7:443)
saving to 'index.html'
index.html           100% |index.html           100% |**********************************| 36362  0:00:00 ETA
'index.html' saved
```

```bash
$ sudo local-gadget trace tcp
CONTAINER        T  PID     COMM             IP  SADDR                  DADDR                  SPORT   DPORT
test-container   C  11039   wget             4   172.17.0.2             188.114.96.7           57560   443
```

### Trace/TcpConnect

The tcpconnect trace gadget traces IPv4 and IPv6 TCP connections.

```bash
$ docker run -it --rm --name test-container busybox /bin/sh -c "wget http://www.example.com"
Connecting to www.example.com (93.184.216.34:80)
saving to 'index.html'
index.html           100% |************************************************************************************************|  1256  0:00:00 ETA
'index.html' saved
```

```bash
$ sudo local-gadget trace tcpconnect --containername test-container
CONTAINER        PID     COMM             IP  SADDR            DADDR            DPORT
test-container   503650  wget             4   172.17.0.3       93.184.216.34    80
```

### Trace/Signal

The signal trace gadget is used to trace system signals received by containers.

```bash
$ docker run -it --rm --name test-container busybox /bin/sh
/ # sleep 100 &
/ # echo $!
7
/ # kill -kill $!
/ # exit
```

```bash
$ sudo local-gadget trace signal --containername test-container
WARN[0000] Runtime enricher (containerd): couldn't get current containers
WARN[0000] Runtime enricher (cri-o): couldn't get current containers
CONTAINER                  PID        COMM          SIGNAL      TPID       RET
test-container             11131      sh            SIGKILL     11162      0
test-container             11131      sh            SIGKILL     7          0
test-container             11131      sh            SIGHUP      11131      0
```

### Trace/SNI
The sni trace gadget is used to trace Server Name Indication (SNI) from TLS requests.
```bash
$ docker run -it --rm --name test-container busybox /bin/sh -c "wget https://example.com"
Connecting to example.com (93.184.216.34:443)
wget: note: TLS certificate validation not implemented
saving to 'index.html'
index.html           100% |*******************************************************************************************************************************************************************|  1256  0:00:00 ETA
'index.html' saved
```
```bash
$ sudo local-gadget trace sni --containername test-container
WARN[0000] Runtime enricher (containerd): couldn't get current containers
WARN[0000] Runtime enricher (cri-o): couldn't get current containers
CONTAINER                                                                                                 NAME
test-container                                                                                            example.com
```


### Traceloop

The `traceloop` gadget is used to trace system calls issued by containers:

```bash
$ docker run -it --rm --name test-container busybox /bin/sh
/ # ls

```

```bash
$ sudo local-gadget traceloop --containername test-container
WARN[0000] Runtime enricher (containerd): couldn't get current containers
WARN[0000] Runtime enricher (cri-o): couldn't get current containers
Tracing syscalls... Hit Ctrl-C to end
^C
CPU PID        COMM             NAME                                       PARAMS                                                                                        RET
...
6   150829     sh               execve                                     filename=18759352 /bin/ls, argv=18759280, envp=18759296                                       0
6   150829     ls               brk                                        brk=0                                                                                         36…
6   150829     ls               brk                                        brk=36440320                                                                                  36…
...
6   150829     ls               write                                      fd=1, buf=5355360 bin   dev   etc   home  pro… 158
6   150829     ls               exit_group                                 error_code=0                                                                                  ...
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
