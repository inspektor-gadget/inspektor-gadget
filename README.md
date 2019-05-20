# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) for developers of
Kubernetes applications. While it is primarily designed for Lokomotive,
Kinvolk's open-source Kubernetes distribution, it can be used on other
Kubernetes distributions.

## How to use

```
$ kubectl gadget
Collection of gadgets for Kubernetes developers

Usage:
  kubectl gadget [command]

Available Commands:
  capabilities Suggest Security Capabilities for securityContext
  execsnoop    Trace new processes
  health       Check the gadget installation on a Kubernetes cluster
  help         Help about any command
  install      Install or reinstall Inspektor Gadget on the worker nodes
  opensnoop    Trace files
  tcpconnect   Suggest Kubernetes Network Policies
  tcptop       Show the TCP traffic in a pod
  traceloop    Get strace-like logs of a pod from the past
  version      Show version

Flags:
  -h, --help                help for kubectl-gadget
      --kubeconfig string   Path to kubeconfig file (default "/home/alban/.kube/config")

Use "kubectl gadget [command] --help" for more information about a command.
```

Inspektor Gadget is a kubectl plugin. It can also be invoked with `kubectl gadget`.

- [Demo: the "execsnoop" gadget](Documentation/demo-execsnoop.md) – watch it [as GIF](Documentation/assets/demo-execsnoop-gifterminal.gif)
- [Demo: the "opensnoop" gadget](Documentation/demo-opensnoop.md) – watch it [as GIF](Documentation/assets/demo-opensnoop-gifterminal.gif)
- [Demo: the "traceloop" gadget](Documentation/demo-traceloop.md) – watch it [as GIF](Documentation/assets/demo-traceloop-gifterminal.gif)
- [Demo: the "capabilities" gadget](Documentation/demo-capabilities.md) – watch is [as GIF](Documentation/assets/demo-capabilities-gifterminal.gif)
- [Demo: the "tcptop" gadget](Documentation/demo-tcptop.md) – watch it [as GIF](Documentation/assets/demo-tcptop-gifterminal.gif)
- [Demo: the "tcpconnect" gadget](Documentation/demo-tcpconnect.md) — watch it [as GIF](Documentation/assets/demo-tcpconnect-gifterminal.gif)

As preview for the above demos, here is the `opensnoop` demo:

![](Documentation/assets/demo-opensnoop-gifterminal.gif)

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DeamonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspector Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

[Read more about the architecture](Documentation/architecture.md)

## Installation

Inspektor Gadget needs some recent Linux features and modifications in Kubernetes present in [Flatcar Linux Edge](https://kinvolk.io/blog/2019/05/introducing-the-flatcar-linux-edge-channel/) and [Lokomotive](https://kinvolk.io/blog/2019/05/driving-kubernetes-forward-with-lokomotive/).

[Read the detailed install instructions](Documentation/install.md)

