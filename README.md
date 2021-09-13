# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes applications. While it was originally designed for [Lokomotive](https://kinvolk.io/lokomotive-kubernetes/), Kinvolk's open-source Kubernetes distribution, it works just as well on other Kubernetes distributions.

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

`kubectl gadget --help` will provide you the list of supported commands and their
flags.

```
$ kubectl gadget --help
Usage:
  kubectl gadget [command]

Available Commands:
  bindsnoop         Trace IPv4 and IPv6 bind() system calls
  capabilities      Trace capabilities security checks triggered by applications
  completion        generate the autocompletion script for the specified shell
  deploy            Deploy Inspektor Gadget on the worker nodes
  dns               Trace DNS requests
  execsnoop         Trace new processes
  help              Help about any command
  network-policy    Generate network policies based on recorded network activity
  opensnoop         Trace open() system calls
  process-collector Collect processes
  profile           Profile CPU usage by sampling stack traces
  socket-collector  Collect sockets
  tcpconnect        Trace TCP connect() system calls
  tcptop            Show the TCP traffic in a pod
  tcptracer         Trace tcp connect, accept and close
  traceloop         Get strace-like logs of a pod from the past
  version           Show version

...
```

### Gadgets Documentation

Specific documentation for the gadgets can be found in the following links:

- [bindsnoop](docs/guides/bindsnoop.md)
- [capabilities](docs/guides/capabilities.md)
- [execsnoop](docs/guides/execsnoop.md)
- [network-policy](docs/guides/network-policy.md)
- [opensnoop](docs/guides/opensnoop.md)
- [profile](docs/guides/profile.md)
- [tcpconnect](docs/guides/tcpconnect.md)
- [tcptop](docs/guides/tcptop.md)
- [traceloop](docs/guides/traceloop.md)

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

You can read further details about the architecture [here](docs/architecture.md).

## Contributing

Contributions are welcome, see [CONTRIBUTING](docs/CONTRIBUTING.md).

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
* [cilium/ebpf](https://github.com/cilium/ebpf): the gadget tracer manager and some other gadgets use the cilium/ebpf library.

## License

The Inspektor Gadget user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
