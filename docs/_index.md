---
content_type: inspektor-gadget
title: Inspektor Gadget
linktitle: Inspektor Gadget
main_menu: true
weight: 40
---

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect
Kubernetes resources and applications. It manages the packaging, deployment and
execution of [eBPF](https://ebpf.io/) programs in a Kubernetes cluster,
including many based on [BCC](https://github.com/iovisor/bcc) tools, as well as
some developed specifically for use in Inspektor Gadget. It automatically maps
low-level kernel primitives to high-level Kubernetes resources, making it easier
and quicker to find the relevant information.

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel eBPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The eBPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What eBPF
programs are and how Inspektor Gadget uses them is briefly explained here:

* [Read more about the architecture](architecture.md)
* [Learn how to install Inspektor Gadget](install.md)
* [Kernel requirements for each gadget](requirements.md)
* [Using `Trace` resources](custom-resources.md)
* [Verify release assets](verify.md)
