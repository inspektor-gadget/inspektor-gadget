---
content_type: inspektor-gadget
title: Inspektor Gadget
linktitle: Inspektor Gadget
main_menu: true
sidebar_position: 1
---

Inspektor Gadget is a set of tools and framework for data collection and system
inspection on Kubernetes clusters and Linux hosts using
[eBPF](https://ebpf.io/). It manages the packaging, deployment and execution of
Gadgets (eBPF programs encapsulated in [OCI
images](https://opencontainers.org/)) and provides mechanisms to customize and
extend Gadget functionality.

## Features

* Build and package eBPF programs into OCI images called Gadgets
* Targets Kubernetes clusters and Linux hosts
* Collect and export data to observability tools with a simple command (and soon via declarative configuration)
* Security mechanisms to restrict and lock-down which Gadgets can be run
* Automatic [enrichment](#what-is-enrichment): map kernel data to high-level resources like Kubernetes and container runtimes
* Supports [WebAssembly](https://webassembly.org/) modules to post-process data and customize IG [operators](#what-is-an-operator); using any WASM-supported language
* Supports many modes of operation; cli, client-server, API, embeddable via Golang library

## Core concepts

### What is a Gadget?

Gadgets are the central component in the Inspektor Gadget framework. A Gadget is
an [OCI image](https://opencontainers.org/) that includes one or more eBPF
programs, metadata YAML file and, optionally, WASM modules for post processing.
As OCI images, they can be stored in a container registry (compliant with the
OCI specifications), making them easy to distribute and share. Gadgets are built
using the [`ig image build`](./gadget-devel/building.md) command.

You can find a growing collection of Gadgets on [Artifact
HUB](https://artifacthub.io/packages/search?kind=22). This includes both in-tree
Gadgets (hosted in this git repository in the
[gadgets](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets)
directory and third-party Gadgets).

See the [Gadget documentation](./gadgets/) for more information.

:::warning For versions prior to v0.31.0

Prior to v0.31.0, Inspektor Gadget only shipped gadgets embedded in its
executable file. As of v0.31.0 these ***built-in*** Gadgets are still available
and work as before, but their use is discouraged as they will be deprecated at
some point. We encourage users to use ***image-based*** Gadgets going forward,
as they provide more features and decouple the eBPF programs from the Inspektor
Gadget release process.

:::

### What is enrichment?

The data that eBPF collects from the kernel includes no knowledge about
Kubernetes, container runtimes or any other high-level user-space concepts. In
order to relate this data to these high-level concepts and make the eBPF data
immediately more understandable, Inspektor Gadget automatically uses kernel
primitives such as mount namespaces, pids or similar to infer which high-level
concepts they relate to; Kubernetes pods, container names, DNS names, etc. The
process of augmenting the eBPF data with these high-level concepts is called
*enrichment*.

Enrichment flows the other way, too. Inspektor Gadget enables users to do
high-performance in-kernel filtering by only referencing high-level concepts
such as Kubernetes pods, container names, etc.; automatically translating these
to the corresponding low-level kernel resources.

### What is an operator?

In Inspektor Gadget, an operator is any part of the framework where an action is
taken. Some operators are under-the-hood (i.e. fetching and loading Gadgets)
while others are user-exposed (enrichment, filtering, export, etc.) and can be
reordered and overridden.

See the [operator documentation](./reference/operators) for more information.

### Further learning

Use the following documents to learn more:

* [Quick Start](./quick-start.md)
* [Gadgets](./gadgets/)
* [Reference](./reference/)
* [Contributing](./devel/contributing.md)
