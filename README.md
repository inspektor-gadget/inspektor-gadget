# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) for developers of
Kubernetes applications. While it is primarily designed for [Lokomotive](https://github.com/kinvolk/lokomotive),
Kinvolk's open-source Kubernetes distribution, it can be used on other
Kubernetes distributions.

## Installation

Install Inspektor Gadget (client-side):

Use [krew](https://sigs.k8s.io/krew) plugin manager to install:

```
kubectl krew install gadget
kubectl gadget --help
```

Install Inspektor Gadget on Kubernetes:

```
$ kubectl gadget deploy | kubectl apply -f -
```

Read the detailed [install instructions](docs/install.md) to find more information.

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
  tcptracer      Trace tcp connect, accept and close
  traceloop      Get strace-like logs of a pod from the past
  version        Show version

Flags:
  -h, --help                help for kubectl gadget
      --kubeconfig string   Path to kubeconfig file (default "/home/alban/.kube/config")

Use "kubectl gadget [command] --help" for more information about a command.
```

- [Demo: the "bindsnoop" gadget](docs/demo-bindsnoop.md)
- [Demo: the "execsnoop" gadget](docs/demo-execsnoop.md) – watch it [as GIF](docs/demos/demo-execsnoop-gifterminal.gif)
- [Demo: the "opensnoop" gadget](docs/demo-opensnoop.md) – watch it [as GIF](docs/demos/demo-opensnoop-gifterminal.gif)
- [Demo: the "traceloop" gadget](docs/demo-traceloop.md) – watch it [as GIF](docs/demos/demo-traceloop-gifterminal.gif)
- [Demo: the "capabilities" gadget](docs/demo-capabilities.md) – watch is [as GIF](docs/demos/demo-capabilities-gifterminal.gif)
- [Demo: the "tcptop" gadget](docs/demo-tcptop.md) – watch it [as GIF](docs/demos/demo-tcptop-gifterminal.gif)
- [Demo: the "tcpconnect" gadget](docs/demo-tcpconnect.md) — watch it [as GIF](docs/demos/demo-tcpconnect-gifterminal.gif)
- [Demo: the "network-policy" gadget](docs/demo-network-policy.md)
- [Demo: the "profile" gadget](docs/demo-profile.md)

As preview for the above demos, here is the `opensnoop` demo:

![](docs/demos/demo-opensnoop-gifterminal.gif)

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

[Read more about the architecture](docs/architecture.md)

## Contributing

Contributions are welcome, see [CONTRIBUTING](CONTRIBUTING.md).

## Discussions

Join the discussions on the [`#inspektor-gadget`](https://kubernetes.slack.com/messages/inspektor-gadget/) channel in the Kubernetes Slack.

## Talks

- Inspektor Gadget and traceloop, [FOSDEM 2020 - Brussels](https://fosdem.org/2020/schedule/event/containers_bpf_tracing/)
- Traceloop for systemd and Kubernetes + Inspektor Gadget, [All Systems Go 2019 - Berlin](https://cfp.all-systems-go.io/ASG2019/talk/98A9LW/)

## Thanks

* [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc): some of the gadgets are based on BCC tools.
* [traceloop](https://github.com/kinvolk/traceloop): the traceloop gadget uses the traceloop tool, which can be used independenly of Kubernetes.
* [gobpf](https://github.com/kinvolk/gobpf): the traceloop gadget heavily uses gobpf.
* [kubectl-trace](https://github.com/iovisor/kubectl-trace): the Inspektor Gadget architecture was inspired from kubectl-trace.
