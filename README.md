# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. It manages the packaging, deployment and execution of custom-built and [BCC](https://github.com/iovisor/bcc)-based BPF programs in a Kubernetes cluster. It automatically maps low-level kernel primitives to high-level Kubernetes resources, making it easier and quicker to find the relevant information.

## The Gadgets

Inspektor Gadget tools are known as gadgets. You can deploy one, two or many gadgets.

Exploring the following documentation will best help you learn which tools can help you in your investigations.

- [bindsnoop](docs/guides/bindsnoop.md)
- [biolatency](docs/guides/biolatency.md)
- [biotop](docs/guides/biotop.md)
- [capabilities](docs/guides/capabilities.md)
- [dns](docs/guides/dns.md)
- [execsnoop](docs/guides/execsnoop.md)
- [filetop](docs/guides/filetop.md)
- [mountsnoop](docs/guides/mountsnoop.md)
- [network-policy](docs/guides/network-policy.md)
- [oomkill](docs/guides/oomkill.md)
- [opensnoop](docs/guides/opensnoop.md)
- [process-collector](docs/guides/process-collector.md)
- [profile](docs/guides/profile.md)
- [seccomp](docs/guides/seccomp.md)
- [socket-collector](docs/guides/socket-collector.md)
- [tcpconnect](docs/guides/tcpconnect.md)
- [tcptop](docs/guides/tcptop.md)
- [traceloop](docs/guides/traceloop.md)

## Installation

Install Inspektor Gadget (client-side):

Use [krew](https://sigs.k8s.io/krew) plugin manager to install:

```bash
$ kubectl krew install gadget
$ kubectl gadget --help
```

Install Inspektor Gadget on Kubernetes:

```bash
$ kubectl gadget deploy | kubectl apply -f -
```

Read the detailed [install instructions](docs/install.md) to find more information.

## How to use

`kubectl gadget --help` will provide you the list of supported commands and their
flags.

```bash
$ kubectl gadget --help
Usage:
  kubectl-gadget [command]

Available Commands:
  bindsnoop         Trace IPv4 and IPv6 bind() system calls
  biolatency        Generate a histogram with the distribution of block device I/O latency
  biotop            Trace block device I/O
  capabilities      Suggest Security Capabilities for securityContext
  completion        generate the autocompletion script for the specified shell
  deploy            Deploy Inspektor Gadget on the cluster
  dns               Trace DNS requests
  execsnoop         Trace new processes
  filetop           Trace reads and writes by file, with container details
  help              Help about any command
  mountsnoop        Trace mount and umount syscalls
  network-policy    Generate network policies based on recorded network activity
  oomkill           Trace the Linux out-of-memory (OOM) killer
  opensnoop         Trace open() system calls
  process-collector Gather information about running processes
  profile           Profile CPU usage by sampling stack traces
  seccomp-advisor   Generate seccomp policies based on recorded syscalls activity
  socket-collector  Gather information about network sockets
  tcpconnect        Trace TCP connect() system calls
  tcptop            Show the TCP traffic in a pod
  tcptracer         Trace tcp connect, accept and close
  traceloop         Get strace-like logs of a pod from the past
  undeploy          Undeploy Inspektor Gadget from cluster
  version           Show version

...
```

## How does it work?

Inspektor Gadget is deployed to each node as a privileged DaemonSet.
It uses in-kernel BPF helper programs to monitor events mainly related to
syscalls from userspace programs in a pod. The BPF programs are run by
the kernel and gather the log data. Inspektor Gadget's userspace
utilities fetch the log data from ring buffers and display it. What BPF
programs are and how Inspektor Gadget uses them is briefly explained here:

You can read further details about the architecture [here](docs/architecture.md).

## Kernel requirements

The different gadgets shipped with Inspektor Gadget use a variety of eBPF
capabilities. The capabilities available depend on the version and
configuration of the kernel running in the node. To be able to run all the
gadgets, you'll need to have at least 5.10 with
[BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled.

See [requirements](docs/requirements.md) for a detailed list of the
requirements per gadget.

## Contributing

Contributions are welcome, see [CONTRIBUTING](docs/CONTRIBUTING.md).

## Discussions

Join the discussions on the [`#inspektor-gadget`](https://kubernetes.slack.com/messages/inspektor-gadget/) channel in the Kubernetes Slack.

## Talks

- Inspektor Gadget and traceloop, [FOSDEM 2020 - Brussels](https://fosdem.org/2020/schedule/event/containers_bpf_tracing/)
- Traceloop for systemd and Kubernetes + Inspektor Gadget, [All Systems Go 2019 - Berlin](https://cfp.all-systems-go.io/ASG2019/talk/98A9LW/)
- Using Inspektor Gadget with OpenShift, [Openshift Commons 2020](https://www.youtube.com/watch?v=X9PI7OWLJSY)
- Using Inspektor Gadget and kubectl-trace, [Open Source Summit EU 2020](https://www.youtube.com/watch?v=2f54ni2X-zo) (live version of the [Cloud Native BPF workshop](https://github.com/kinvolk/cloud-native-bpf-workshop))
- Inspektor Gadget, introduction and demos, [eCHO Livestream - September 2021](https://www.youtube.com/watch?v=RZ2qNm_vlUc)

## Thanks

* [BPF Compiler Collection (BCC)](https://github.com/iovisor/bcc): some of the gadgets are based on BCC tools.
* [traceloop](https://github.com/kinvolk/traceloop): the traceloop gadget uses the traceloop tool, which can be used independently of Kubernetes.
* [gobpf](https://github.com/kinvolk/gobpf): the traceloop gadget heavily uses gobpf.
* [kubectl-trace](https://github.com/iovisor/kubectl-trace): the Inspektor Gadget architecture was inspired from kubectl-trace.
* [cilium/ebpf](https://github.com/cilium/ebpf): the gadget tracer manager and some other gadgets use the cilium/ebpf library.

## License

The Inspektor Gadget user space components are licensed under the
[Apache License, Version 2.0](LICENSE). The BPF code templates are licensed
under the [General Public License, Version 2.0, with the Linux-syscall-note](LICENSE-bpf.txt).
