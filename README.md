<h1 align="center">
  <picture>
    <source media="(prefers-color-scheme: light)" srcset="docs/images/logo/ig-logo-horizontal.svg">
    <img src="docs/images/logo/ig-logo-horizontal.svg" alt="Inspektor Gadget Logo" width="80%">
  </picture>
</h1>

[![Inspektor Gadget CI](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml/badge.svg)](https://github.com/inspektor-gadget/inspektor-gadget/actions/workflows/inspektor-gadget.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/inspektor-gadget/inspektor-gadget.svg)](https://pkg.go.dev/github.com/inspektor-gadget/inspektor-gadget)
[![Go Report Card](https://goreportcard.com/badge/github.com/inspektor-gadget/inspektor-gadget)](https://goreportcard.com/report/github.com/inspektor-gadget/inspektor-gadget)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/7962/badge)](https://www.bestpractices.dev/projects/7962)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/inspektor-gadget/inspektor-gadget/badge)](https://scorecard.dev/viewer/?uri=github.com/inspektor-gadget/inspektor-gadget)
[![Inspektor Gadget Test Reports](https://img.shields.io/badge/Link-Test%20Reports-blue)](https://inspektor-gadget.github.io/ig-test-reports)
[![Inspektor Gadget Benchmarks](https://img.shields.io/badge/Link-Benchmarks-blue)](https://inspektor-gadget.github.io/ig-benchmarks/dev/bench)
[![Release](https://img.shields.io/github/v/release/inspektor-gadget/inspektor-gadget)](https://github.com/inspektor-gadget/inspektor-gadget/releases)
[![Artifact Hub: Gadgets](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/gadgets)](https://artifacthub.io/packages/search?repo=gadgets)
[![Artifact Hub: Helm charts](https://img.shields.io/endpoint?url=https://artifacthub.io/badge/repository/helm-charts)](https://artifacthub.io/packages/helm/gadget/gadget)
[![Slack](https://img.shields.io/badge/slack-%23inspektor--gadget-brightgreen.svg?logo=slack)](https://kubernetes.slack.com/messages/inspektor-gadget/)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE)
[![License: GPL v2](https://img.shields.io/badge/License-GPL%20v2-blue.svg)](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/LICENSE-bpf.txt)

Inspektor Gadget is a set of tools and framework for data collection and system inspection on Kubernetes clusters and Linux hosts using [eBPF](https://ebpf.io/). It manages the packaging, deployment and execution of Gadgets (eBPF programs encapsulated in [OCI images](https://opencontainers.org/)) and provides mechanisms to customize and extend Gadget functionality.

## Features

* Build and package eBPF programs into OCI images called Gadgets
* Targets Kubernetes clusters and Linux hosts
* Collect and export data to observability tools with a simple command (and soon via declarative configuration)
* Security mechanisms to restrict and lock-down which Gadgets can be run
* Automatic [enrichment](#what-is-enrichment): map kernel data to high-level resources like Kubernetes and container runtimes
* Supports [WebAssembly](https://webassembly.org/) modules to post-process data and customize IG [operators](#what-is-an-operator); using any WASM-supported language
* Supports many modes of operation; cli, client-server, API, embeddable via Golang library

## Quick start

This assumes you have the required Inspektor Gadget tools installed as outlined in the [Installation instructions](#installation).

The following examples use the [trace_open Gadget](https://www.inspektor-gadget.io/docs/latest/gadgets/trace_open) which triggers when a file is open on the system.

### Kubernetes

Deploy and run on a Kubernetes cluster

```bash
kubectl gadget deploy
kubectl gadget run trace_open
```

Or use via `kubectl debug` (requires no installation) for a single node

```bash
kubectl debug --profile=sysadmin node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig -- ig run trace_open
```

### Linux

Runs Inspektor Gadget locally on Linux.

```bash
ig run trace_open
```

### Via Docker

```bash
docker run -ti --rm --privileged -v /:/host --pid=host ghcr.io/inspektor-gadget/ig run trace_open
```

### MacOS or Windows (but not exclusively)

Run the following on a Linux machine to make `ig` available to clients.

```bash
ig daemon --host=tcp://0.0.0.0:1234
```

Use the `gadgetctl` client to connect and run commands remote Linux servers.

```bash
gadgetctl run trace_open --remote-address=tcp://$IP:1234
```

***The above demonstrates the simplest command. To learn how to filter, export, etc. please consult the documentation for the [run](https://www.inspektor-gadget.io/docs/latest/reference/run) command***.

## Core concepts

### What is a Gadget?

Gadgets are the central component in the Inspektor Gadget framework. A Gadget is an [OCI image](https://opencontainers.org/) that includes one or more eBPF programs, metadata YAML file and, optionally, WASM modules for post processing.
As OCI images, they can be stored in a container registry (compliant with the OCI specifications), making them easy to distribute and share.
Gadgets are built using the [`ig image build`](/docs/gadg) command.

You can find a growing collection of Gadgets on [Artifact HUB](https://artifacthub.io/packages/search?kind=22). This includes both in-tree Gadgets (hosted in this git repository in the [/gadgets](./gadgets/README.md) directory and third-party Gadgets).

See the [Gadget documentation](https://www.inspektor-gadget.io/docs/latest/gadgets/) for more information.

#### :warning: For versions prior to v0.31.0

Prior to v0.31.0, Inspektor Gadget only shipped gadgets embedded in its executable file. As of v0.31.0 these ***built-in*** Gadgets are still available and work as before, but their use is discouraged as they will be deprecated at some point. We encourage users to use ***image-based*** Gadgets going forward, as they provide more features and decouple the eBPF programs from the Inspektor Gadget release process.

### What is enrichment?

The data that eBPF collects from the kernel includes no knowledge about Kubernetes, container
runtimes or any other high-level user-space concepts. In order to relate this data to these high-level
concepts and make the eBPF data immediately more understandable, Inspektor Gadget automatically
uses kernel primitives such as mount namespaces, pids or similar to infer which high-level
concepts they relate to; Kubernetes pods, container names, DNS names, etc. The process of augmenting
the eBPF data with these high-level concepts is called *enrichment*.

Enrichment flows the other way, too. Inspektor Gadget enables users to do high-performance
in-kernel filtering by only referencing high-level concepts such as Kubernetes pods, container
names, etc.; automatically translating these to the corresponding low-level kernel resources.

See the [enrichment documentation](docs/enrichment)

### What is an operator?

In Inspektor Gadget, an operator is any part of the framework where an action is taken. Some operators are under-the-hood (i.e. fetching and loading Gadgets) while others are user-exposed (enrichment, filtering, export, etc.) and can be reordered and overridden.

See the [operator documentation](docs/operators.md) for more information.

### Further learning

Use the [project documentation](/docs/_index.md) to learn more about:

* [Overview](/docs/_index.md)
* [Concepts](/docs/core_concepts/_index.md)
* [Components](https://inspektor-gadget.io/docs/components)
* [Gadgets](https://inspektor-gadget.io/docs/gadgets)
* [Reference](https://inspektor-gadget.io/docs/reference)
* [Contributing]()

## Installation

Inspektor Gadget can be installed in several different ways depending on your environment and needs.

### For Kubernetes

Use the [krew](https://sigs.k8s.io/krew) plugin manager to install the gadget `kubectl` plugin and
deploy Inspektor Gadget into a Kubernetes cluster.

```bash
kubectl krew install gadget
kubectl gadget deploy
```
### On Linux

This installs the `ig` and `gadgetctl` tools

```bash
IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)
IG_ARCH=amd64

# ig binary
curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - ig

# gadgetctl binary
curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/gadgetctl-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - gadgetctl
```

### On MacOS

Download the `gadgetctl` client tool
([amd64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-amd64-v0.30.0.tar.gz),
[arm64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-arm64-v0.30.0.tar.gz))
which enables communicating with `ig` running in daemon mode on a Linux host.

### On Windows

Download the
[gadgetctl](https://github.com/inspektor-gadget/inspektor-gadget/releases/latest/download/gadgetctl-windows-amd64-v0.30.0.tar.gz)
client tool which enables communicating with ig running in daemon mode on a
Linux host.

Download the  directly

Read the detailed [install
instructions](https://www.inspektor-gadget.io/docs/latest/getting-started/) for more information.

## Kernel requirements

Kernel requirements are largely determined by the specific eBPF functionality a Gadget makes use of.
The eBPF functionality available to Gadgets depend on the version and configuration of the kernel running
running in the node/machine where the Gadget is being loaded. Gadgets developed by the Inspektor
Gadget project require at least Linux 5.10 with [BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled.

Refer to the [documentation for a specific Gadget](/gadgets/README.md) for any notes regarding requirements.

## Code examples

There are some examples in [this](./examples/) folder showing the usage
of the Golang packages provided by Inspektor Gadget. These examples are
designed for developers that want to use the Golang packages exposed by
Inspektor Gadget directly. End-users do not need this and can use
`kubectl-gadget` or `ig` directly.

## Contributing

Contributions are welcome, see [CONTRIBUTING](docs/devel/CONTRIBUTING.md).

## Community Meeting

We hold community meetings regularly. Please check our [calendar](https://calendar.google.com/calendar/u/0/embed?src=ac93fb85a1999d57dd97cce129479bb2741946e1d7f4db918fe14433c192152d@group.calendar.google.com)
for the full schedule of up-coming meetings and please add any topic you want to discuss to our [meeting
notes](https://docs.google.com/document/d/1cbPYvYTsdRXd41PEDcwC89IZbcA8WneNt34oiu5s9VA/edit)
document.

## Slack

Join the discussions on the [`#inspektor-gadget`](https://kubernetes.slack.com/messages/inspektor-gadget/) channel in the Kubernetes Slack.

## Talks

- [Collecting Low-Level Metrics with eBPF, KubeCon + CloudNativeCon North America 2023](https://kccncna2023.sched.com/event/a70c0a016973beb5705f5f72fa58f622) ([video](https://www.youtube.com/watch?v=_ft3iTw5uv8), [slides](https://static.sched.com/hosted_files/kccncna2023/91/Collecting%20Low-Level%20Metrics%20with%20eBPF.pdf))
- [A (re)introduction of Inspektor Gadget: A Containerized Framework for eBPF Systems Inspection, Cloud Native Rejekts Chicago - November 2023](https://cfp.cloud-native.rejekts.io/cloud-native-rejekts-na-chicago-2023/talk/KNU8SK/) ([video](https://youtu.be/KzQ_Whn6oBA?list=PLnfCaIV4aZe-4zfJeSl1bN9xKBhlIEGSt&t=7804))
- [Gaining Linux insights with Inspektor Gadget, an eBPF tool and systems inspection framework, All Systems Go - September 2023](https://cfp.all-systems-go.io/all-systems-go-2023/talk/ZSTFTF/) ([video](https://www.youtube.com/watch?v=yJsPufVD0hY))
- Overcoming the Challenges of Debugging Containers, Container Days Hamburg - September 2023 ([video](https://www.youtube.com/watch?v=MC6BkV09GT0))
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

The Inspektor Gadget user-space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
