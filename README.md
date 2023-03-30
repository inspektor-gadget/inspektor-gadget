<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/logo-horizontal.png">
    <img src="docs/images/logo/logo-horizontal-dark.png" alt="Inspektor Gadget" width="80%">
  </picture>
</h1>

[![Inspektor Gadget CI](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml/badge.svg)](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/inspektor-gadget/inspektor-gadget.svg)](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget)
[![Go Report Card](https://goreportcard.com/badge/github.com/inspektor-gadget/inspektor-gadget)](https://goreportcard.com/report/github.com/inspektor-gadget/inspektor-gadget)
[![Release](https://img.shields.io/github/v/release/inspektor-gadget/inspektor-gadget)](https://github.com/inspektor-gadget/inspektor-gadget/releases)
[![Slack](https://img.shields.io/badge/slack-%23inspektor--gadget-brightgreen.svg?logo=slack)](https://kubernetes.slack.com/messages/inspektor-gadget/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE-bpf.txt)

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect
Kubernetes resources and applications. It manages the packaging, deployment and
execution of [eBPF](https://ebpf.io/) programs in a Kubernetes cluster,
including many based on [BCC](https://github.com/iovisor/bcc) tools, as well as
some developed specifically for use in Inspektor Gadget. It automatically maps
low-level kernel primitives to high-level Kubernetes resources, making it easier
and quicker to find the relevant information.

## The Gadgets

Inspektor Gadget tools are known as gadgets. You can deploy one, two or many gadgets.

Explore the following documentation to find out which tools can help you in your investigations.

- `advise`:
	- [`network-policy`](docs/gadgets/advise/network-policy.md)
	- [`seccomp-profile`](docs/gadgets/advise/seccomp-profile.md)
- `audit`:
	- [`seccomp`](docs/gadgets/audit/seccomp.md)
- `profile`:
	- [`block-io`](docs/gadgets/profile/block-io.md)
	- [`cpu`](docs/gadgets/profile/cpu.md)
- `snapshot`:
	- [`process`](docs/gadgets/snapshot/process.md)
	- [`socket`](docs/gadgets/snapshot/socket.md)
- `top`:
	- [`block-io`](docs/gadgets/top/block-io.md)
	- [`ebpf`](docs/gadgets/top/ebpf.md)
	- [`file`](docs/gadgets/top/file.md)
	- [`tcp`](docs/gadgets/top/tcp.md)
- `trace`:
	- [`bind`](docs/gadgets/trace/bind.md)
	- [`capabilities`](docs/gadgets/trace/capabilities.md)
	- [`dns`](docs/gadgets/trace/dns.md)
	- [`exec`](docs/gadgets/trace/exec.md)
	- [`fsslower`](docs/gadgets/trace/fsslower.md)
	- [`mount`](docs/gadgets/trace/mount.md)
	- [`oomkill`](docs/gadgets/trace/oomkill.md)
	- [`open`](docs/gadgets/trace/open.md)
	- [`signal`](docs/gadgets/trace/signal.md)
	- [`sni`](docs/gadgets/trace/sni.md)
	- [`tcp`](docs/gadgets/trace/tcp.md)
	- [`tcpconnect`](docs/gadgets/trace/tcpconnect.md)
- [`traceloop`](docs/gadgets/traceloop.md)

## Installation

Install Inspektor Gadget (client-side):

Use [krew](https://sigs.k8s.io/krew) plugin manager to install:

```bash
$ kubectl krew install gadget
```

Install Inspektor Gadget on Kubernetes:

```bash
$ kubectl gadget deploy
```

Read the detailed [install instructions](docs/install.md) to find more information.

## How to use

`kubectl gadget --help` will provide you the list of supported commands and their flags.

```bash
$ kubectl gadget --help
Collection of gadgets for Kubernetes developers

Usage:
  kubectl-gadget [command]

Available Commands:
  advise         Recommend system configurations based on collected information
  audit          Audit a subsystem
  completion     Generate the autocompletion script for the specified shell
  deploy         Deploy Inspektor Gadget on the cluster
  help           Help about any command
  profile        Profile different subsystems
  snapshot       Take a snapshot of a subsystem and print it
  top            Gather, sort and periodically report events according to a given criteria
  trace          Trace and print system events
  traceloop      Get strace-like logs of a container from the past
  undeploy       Undeploy Inspektor Gadget from cluster
  update-catalog Download a new gadget catalog from the nodes to have it in sync with this client
  version        Show version

...
```

You can then get help for each subcommand:

```bash
$ kubectl gadget advise --help
Recommend system configurations based on collected information

Usage:
  kubectl-gadget advise [command]

Available Commands:
  network-policy  Generate network policies based on recorded network activity
  seccomp-profile Generate seccomp profiles based on recorded syscalls activity

...
$ kubectl gadget audit --help
Audit a subsystem

Usage:
  kubectl-gadget audit [command]

Available Commands:
  seccomp     Audit syscalls according to the seccomp profile

...
$ kubectl gadget profile --help
Profile different subsystems

Usage:
  kubectl-gadget profile [command]

Available Commands:
  block-io    Analyze block I/O performance through a latency distribution
  cpu         Analyze CPU performance by sampling stack traces

...
$ kubectl gadget snapshot --help
Take a snapshot of a subsystem and print it

Usage:
  kubectl-gadget snapshot [command]

Available Commands:
  process     Gather information about running processes
  socket      Gather information about TCP and UDP sockets

...
$ kubectl gadget top --help
Gather, sort and periodically report events according to a given criteria

Usage:
  kubectl-gadget top [command]

Available Commands:
  block-io    Periodically report block device I/O activity
  ebpf        Periodically report ebpf runtime stats
  file        Periodically report read/write activity by file
  tcp         Periodically report TCP activity

...
$ kubectl gadget trace --help
Trace and print system events

Usage:
  kubectl-gadget trace [command]

Available Commands:
  bind         Trace socket bindings
  capabilities Trace security capability checks
  dns          Trace DNS requests
  exec         Trace new processes
  fsslower     Trace open, read, write and fsync operations slower than a threshold
  mount        Trace mount and umount system calls
  network      Trace network streams
  oomkill      Trace when OOM killer is triggered and kills a process
  open         Trace open system calls
  signal       Trace signals received by processes
  sni          Trace Server Name Indication (SNI) from TLS requests
  tcp          Trace TCP connect, accept and close
  tcpconnect   Trace connect system calls

...
```

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel eBPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The eBPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What eBPF
programs are and how Inspektor Gadget uses them is briefly explained here:

You can read further details about the architecture [here](docs/architecture.md).

## `ig`

Inspektor Gadget can also be used without Kubernetes to trace containers with
the [`ig`](docs/ig.md) tool.

## Kernel requirements

The different gadgets shipped with Inspektor Gadget use a variety of eBPF
capabilities. The capabilities available depend on the version and
configuration of the kernel running in the node. To be able to run all the
gadgets, you'll need to have at least 5.10 with
[BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled.

See [requirements](docs/requirements.md) for a detailed list of the
requirements per gadget.

## Code examples

There are some examples in [this](./examples/) folder showing the usage
of the Golang packages provided by Inspektor Gadget. These examples are
designed for developers that want to use the Golang packages exposed by
Inspektor Gadget directly. End-users do not need this and can use
`kubectl-gadget` or `ig` directly.

## Contributing

Contributions are welcome, see [CONTRIBUTING](docs/devel/CONTRIBUTING.md).

## Discussions

Join the discussions on the [`#inspektor-gadget`](https://kubernetes.slack.com/messages/inspektor-gadget/) channel in the Kubernetes Slack.

## Talks

- [Using the EBPF Superpowers To Generate Kubernetes Security Policies, KubeCon + CloudNativeCon North America 2022](https://sched.co/182GW) ([video](https://www.youtube.com/watch?v=3dysej_Ydcw), [slides](https://static.sched.com/hosted_files/kccncna2022/5a/Using%20eBPF%20Superpowers%20to%20generate%20Kubernetes%20Security%20Policies.pdf))
- [Debug Your Clusters with eBPF-Powered Tools, Cloud Native eBPF Day North America 2022](https://sched.co/1Auyw) ([video](https://www.youtube.com/watch?v=6s109Uwr608), [slides](https://static.sched.com/hosted_files/cloudnativeebpfdayna22/10/Debug%20Your%20Clusters%20with%20eBPF-Powered%20Tools.pdf))
- [Who Needs an API Server to Debug a Kubernetes Cluster?, Cloud Native eBPF Day North America 2022](https://sched.co/1Auz8) ([video](https://www.youtube.com/watch?v=pGLl7Tdw4Zo), [slides](https://static.sched.com/hosted_files/cloudnativeebpfdayna22/01/WhoNeedsAnAPIServerToDebugAKubernetesCluster.pdf))
- Inspektor Gadget, introduction and demos, eCHO Livestream - September 2021 ([video](https://www.youtube.com/watch?v=RZ2qNm_vlUc))
- OpenShift Commons Briefing: Unleash eBPF Superpowers with Kubectl Gadget, Openshift Commons 2020 ([video](https://www.youtube.com/watch?v=X9PI7OWLJSY))
- [Tutorial: Understanding What Happens Inside Kubernetes Clusters Using BPF Tools, Open Source Summit EU 2020](https://events.linuxfoundation.org/archive/2020/open-source-summit-europe/program/schedule/) ([video](https://www.youtube.com/watch?v=2f54ni2X-zo))
- [Inspektor Gadget and traceloop: Tracing containers syscalls using BPF, FOSDEM 2020](https://fosdem.org/2020/schedule/event/containers_bpf_tracing/) ([video](https://www.youtube.com/watch?v=tcwmAAJATkc), [slides](https://archive.fosdem.org/2020/schedule/event/containers_bpf_tracing/attachments/slides/4029/export/events/attachments/containers_bpf_tracing/slides/4029/Inspektor_Gadget_and_traceloop_FOSDEM.pdf))
- Traceloop for systemd and Kubernetes + Inspektor Gadget, All Systems Go 2019 ([video](https://www.youtube.com/watch?v=T-kTXo7X93M))

## Thanks

* [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc): some of the gadgets are based on BCC tools.
* [kubectl-trace](https://github.com/iovisor/kubectl-trace): the Inspektor Gadget architecture was inspired from kubectl-trace.
* [cilium/ebpf](https://github.com/cilium/ebpf): the gadget tracer manager and some other gadgets use the cilium/ebpf library.

## License

The Inspektor Gadget user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
