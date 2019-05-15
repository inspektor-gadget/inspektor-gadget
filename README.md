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
  hints-network         Get network policy hints suited for your app
```

Inspektor Gadget is a kubectl plugin. It can also be invoked with `kubectl gadget`.

- [Demo: the "execsnoop" gadget](Documentation/demo-execsnoop.md) – watch it [as GIF](Documentation/demo-execsnoop-gifterminal.md)
- [Demo: the "straceback" gadget](Documentation/demo-straceback.md) – watch it [as GIF](Documentation/demo-straceback-gifterminal.md)
- [Demo: the "tcptop" gadget](Documentation/demo-tcptop.md) – watch it [as GIF](Documentation/demo-tcptop-gifterminal.md)
- [Demo: the "hints-network" gadget](Documentation/demo-hints-network.md) — watch it [as GIF](Documentation/demo-hints-network-gifterminal.md)

## How does it work?

[architecture](Documentation/architecture.md)

## Installation

[install](Documentation/install.md)

