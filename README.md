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
  bindsnoop      Trace IPv4 and IPv6 bind() system calls
  capabilities   Suggest Security Capabilities for securityContext
  deploy         Deploy Inspektor Gadget on the worker nodes
  execsnoop      Trace new processes
  help           Help about any command
  network-policy Generate network policies based on recorded network activity
  opensnoop      Trace files
  profile        Profile CPU usage by sampling stack traces
  tcpconnect     Suggest Kubernetes Network Policies
  tcptop         Show the TCP traffic in a pod
  tcptracer      trace tcp connect, accept and close
  traceloop      Get strace-like logs of a pod from the past
  version        Show version

Flags:
  -h, --help                help for kubectl-gadget
      --kubeconfig string   Path to kubeconfig file (default "/home/alban/.kube/config")

Use "kubectl gadget [command] --help" for more information about a command.
```

Inspektor Gadget is a kubectl plugin. It can also be invoked with `kubectl gadget`.

- [Demo: the "bindsnoop" gadget](Documentation/demo-bindsnoop.md)
- [Demo: the "execsnoop" gadget](Documentation/demo-execsnoop.md) – watch it [as GIF](Documentation/demos/demo-execsnoop-gifterminal.gif)
- [Demo: the "opensnoop" gadget](Documentation/demo-opensnoop.md) – watch it [as GIF](Documentation/demos/demo-opensnoop-gifterminal.gif)
- [Demo: the "traceloop" gadget](Documentation/demo-traceloop.md) – watch it [as GIF](Documentation/demos/demo-traceloop-gifterminal.gif)
- [Demo: the "capabilities" gadget](Documentation/demo-capabilities.md) – watch is [as GIF](Documentation/demos/demo-capabilities-gifterminal.gif)
- [Demo: the "tcptop" gadget](Documentation/demo-tcptop.md) – watch it [as GIF](Documentation/demos/demo-tcptop-gifterminal.gif)
- [Demo: the "tcpconnect" gadget](Documentation/demo-tcpconnect.md) — watch it [as GIF](Documentation/demos/demo-tcpconnect-gifterminal.gif)
- [Demo: the "network-policy" gadget](Documentation/demo-network-policy.md)
- [Demo: the "profile" gadget](Documentation/demo-profile.md)

As preview for the above demos, here is the `opensnoop` demo:

![](Documentation/demos/demo-opensnoop-gifterminal.gif)

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

[Read more about the architecture](Documentation/architecture.md)

## Gadgets

Not all gadgets currently work everywhere.

| Gadget            | Flatcar Edge | Flatcar Stable | Minikube | GKE |
|-------------------|:------------:|:--------------:|:--------:|:---:|
| traceloop         |       ✔️      |        ✔️       |     ✔️    |  ✔️  |
| network-policy    |       ✔️      |        ✔️       |     ✔️    |  ✔️  |
| tcptracer         |       ✔️      |                |          |     |
| tcpconnect        |       ✔️      |                |          |     |
| tcptop            |       ✔️      |                |          |     |
| execsnoop         |       ✔️      |                |          |     |
| opensnoop         |       ✔️      |                |          |     |
| bindsnoop         |       ✔️      |                |          |     |
| capabilities      |       ✔️      |                |          |     |
| profile           |       ✔️      |                |          |     |

Inspektor Gadget needs some recent Linux features and modifications in Kubernetes present in [Flatcar Container Linux Edge](https://kinvolk.io/blog/2019/05/introducing-the-flatcar-linux-edge-channel/) and [Lokomotive](https://kinvolk.io/blog/2019/05/driving-kubernetes-forward-with-lokomotive/). [More details in the detailed install instructions](Documentation/install.md)

## Installation

Install Inspektor Gadget (client-side):

```
$ wget https://github.com/kinvolk/inspektor-gadget/releases/download/v0.1.0-alpha.5/inspektor-gadget.tar.gz
$ tar xvf inspektor-gadget.tar.gz
$ sudo cp inspektor-gadget/inspektor-gadget /usr/local/bin/kubectl-gadget
$ kubectl gadget version
```

Install Inspektor Gadget on Kubernetes:

```
$ kubectl gadget deploy | kubectl apply -f -
```

[Read the detailed install instructions](Documentation/install.md)

## Contributing

Contributions are welcome!

If you're looking where to start, you can check the issues with the 'good first issue' label on [Inspektor Gadget](https://github.com/kinvolk/inspektor-gadget/issues?q=is%3Aissue+is%3Aopen+label%3A%22good+first+issue%22) or [traceloop](https://github.com/kinvolk/traceloop/issues?q=is%3Aopen+is%3Aissue+label%3A%22good+first+issue%22). Don't hesitate to [talk with us](https://github.com/kinvolk/inspektor-gadget#discussions) if you need further help.

## Discussions

Join the discussions on the `#inspektor-gadget` channel in the [Kubernetes Slack](http://kubernetes.slack.com/).

## Thanks

* [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc): the execsnoop, opensnoop, tcptop and tcpconnect gadgets use programs from BCC.
* [traceloop](https://github.com/kinvolk/traceloop): the traceloop gadget uses the traceloop tool, which can be used independenly of Kubernetes.
* [gobpf](https://github.com/kinvolk/gobpf): the traceloop gadget heavily uses gobpf.
* [kubectl-trace](https://github.com/iovisor/kubectl-trace): the Inspektor Gadget architecture was inspired from kubectl-trace.
