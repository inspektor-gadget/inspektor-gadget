---
content_type: inspektor-gadget
title: Inspektor Gadget
linktitle: Inspektor Gadget
main_menu: true
weight: 40
---

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes applications. While it was originally designed for [Lokomotive](https://kinvolk.io/lokomotive-kubernetes/), Kinvolk's open-source Kubernetes distribution, it works just as well on other Kubernetes distributions.

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

## Further Reading

* [Read more about the architecture](architecture.md)
* [Learn how to install Inspektor Gadget](install.md)
* [Kernel requirements for each gadget](requirements.md)
* [Using `Trace` resources](custom-resources.md)
