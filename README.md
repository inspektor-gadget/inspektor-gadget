# Inspektor Gadget

Inspektor Gadget is a collection of tools (or gadgets) to debug and inspect Kubernetes resources and applications. It manages the packaging, deployment and execution of custom-built and [BCC](https://github.com/iovisor/bcc)-based BPF programs in a Kubernetes cluster. It automatically maps low-level kernel primitives to high-level Kubernetes resources, making it easier and quicker to find the relevant information.

## The Gadgets

Inspektor Gadget tools are known as gadgets. You can deploy one, two or many gadgets.

Exploring the following documentation will best help you learn which tools can help you in your investigations.

- [audit-seccomp](docs/guides/audit-seccomp.md)
- [network-policy](docs/guides/network-policy.md)
- `profile`:
	- [`block-io`](docs/guides/profile/block-io.md)
	- [`cpu`](docs/guides/profile/cpu.md)
- [seccomp](docs/guides/seccomp.md)
- `snapshot`:
	- [`process`](docs/guides/snapshot/process.md)
	- [`socket`](docs/guides/snapshot/socket.md)
- `top`:
	- [`block-io`](docs/guides/top/block-io.md)
	- [`file`](docs/guides/top/file.md)
	- [`tcp`](docs/guides/top/tcp.md)
- `trace`:
	- [`bind`](docs/guides/trace/bind.md)
	- [`capabilities`](docs/guides/trace/capabilities.md)
	- [`dns`](docs/guides/trace/dns.md)
	- [`exec`](docs/guides/trace/exec.md)
	- [`fsslower`](docs/guides/trace/fsslower.md)
	- [`mount`](docs/guides/trace/mount.md)
	- [`oomkill`](docs/guides/trace/oomkill.md)
	- [`open`](docs/guides/trace/open.md)
	- [`signal`](docs/guides/trace/signal.md)
	- [`tcp`](docs/guides/trace/tcp.md)
	- [`tcpconnect`](docs/guides/trace/tcpconnect.md)
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

`kubectl gadget --help` will provide you the list of supported commands and their flags.

```bash
$ kubectl gadget --help
Collection of gadgets for Kubernetes developers

Usage:
  kubectl-gadget [command]

Available Commands:
  audit-seccomp   Trace syscalls that seccomp sent to the audit log
  biotop          Trace block devices I/O, with container details
  completion      generate the autocompletion script for the specified shell
  deploy          Deploy Inspektor Gadget on the cluster
  help            Help about any command
  network-policy  Generate network policies based on recorded network activity
  profile         Profile different subsystems
  seccomp-advisor Generate seccomp policies based on recorded syscalls activity
  snapshot        Take a snapshot of a subsystem and print it
  tcptop          Trace TCP connection, with container details
  top             Gather, sort and print events according to a given criteria
  trace           Trace and print system events
  traceloop       Get strace-like logs of a pod from the past
  undeploy        Undeploy Inspektor Gadget from cluster
  version         Show version

...
```

You can then get help for each subcommand:

```bash
$ kubectl gadget profile --help
Profile different subsystems

Usage:
  kubectl-gadget profile [command]

Available Commands:
  block-io    Generate a histogram with the distribution of block device I/O latency
  cpu         Profile CPU usage by sampling stack traces

...
$ kubectl gadget snapshot --help
Take a snapshot of a subsystem and print it

Usage:
  kubectl-gadget snapshot [command]

Available Commands:
  process     Gather information about running processes
  socket      Gather information about network sockets

...
$ kubectl gadget top --help
Gather, sort and print events according to a given criteria

Usage:
  kubectl-gadget top [command]

Available Commands:
  block-io    Trace block devices I/O
  file        Trace reads and writes by file
  tcp         Trace TCP connection

...
$ kubectl gadget trace --help
Trace and print system events

Usage:
  kubectl-gadget trace [command]

Available Commands:
  bind         Trace the kernel functions performing socket binding
  capabilities Trace security capability checks
  dns          Trace DNS requests
  exec         Trace new processes
  fsslower     Trace open, read, write and fsync operations slower than a threshold
  mount        Trace mount and umount system calls
  oomkill      Trace when OOM killer is triggered and kills a process
  open         Trace open system calls
  signal       Trace signals received by processes
  sni          Trace Server Name Indicator requests
  tcp          Trace tcp connect, accept and close
  tcpconnect   Trace connect system calls

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
