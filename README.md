# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) for developers of
Kubernetes applications. While it is primarily designed for Lokomotive,
Kinvolk's open-source Kubernetes distribution, it can be used on other
Kubernetes distributions.

## How to use

```
$ inspektor-gadget
inspektor-gadget is a collection of gadgets for Kubernetes developers.

List of gadgets:
  execsnoop             Watch programs being executed in pods
  opensnoop             Watch files being opened in pods
  tcptop                Monitor the network traffic in pods
  straceback            Get strace-like logs of a pod from the past
  capabilities          Suggest security capabilities for securityContext
  hints-network         Get network policy hints suited for your app
```

Inspektor Gadget is a kubectl plugin. It can also be invoked with `kubectl gadget`.

- [Demo: the "execsnoop" gadget](Documentation/demo-execsnoop.md) – watch it [as GIF](Documentation/demo-execsnoop-gifterminal.md)
- [Demo: the "opensnoop" gadget](Documentation/demo-opensnoop.md) – watch it [as GIF](Documentation/demo-opensnoop-gifterminal.md)
- [Demo: the "straceback" gadget](Documentation/demo-straceback.md) – watch it [as GIF](Documentation/demo-straceback-gifterminal.md)
- [Demo: the "capabilities" gadget](Documentation/demo-capabilities.md) – watch is [as GIF](Documentation/demo-capabilities-gifterminal.md)
- [Demo: the "tcptop" gadget](Documentation/demo-tcptop.md) – watch it [as GIF](Documentation/demo-tcptop-gifterminal.md)
- [Demo: the "hints-network" gadget](Documentation/demo-hints-network.md) — watch it [as GIF](Documentation/demo-hints-network-gifterminal.md)

As preview for the above demos, here is the `opensnoop` demo:

![](Documentation/demo-opensnoop-gifterminal.gif)

(Click on the image above and then click *Download* to enlarge.)

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

