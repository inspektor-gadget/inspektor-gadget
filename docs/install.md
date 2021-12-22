---
title: Installation
weight: 10
description: >
  How to install.
---

<!-- toc -->
- [Installing kubectl gadget](#installing-kubectl-gadget)
  * [Using krew](#using-krew)
  * [Install a specific release](#install-a-specific-release)
  * [Compile from the sources](#compile-from-the-sources)
- [Installing in the cluster](#installing-in-the-cluster)
  * [Quick installation](#quick-installation)
  * [Choosing the gadget image](#choosing-the-gadget-image)
  * [Hook Mode](#hook-mode)
  * [Specific Information for Different Platforms](#specific-information-for-different-platforms)
    + [Minikube](#minikube)
<!-- /toc -->

Inspektor Gadget is composed by a `kubectl` plugin executed in the user's
system and a DaemonSet deployed in the cluster.

## Installing kubectl gadget

Choose one way to install the Inspektor Gadget `kubectl` plugin.

### Using krew

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl gadget` by executing the following
commands.

```
kubectl krew install gadget
kubectl gadget --help
```

### Install a specific release

Download the asset for a given release and platform from the
[releases page](https://github.com/kinvolk/inspektor-gadget/releases/),
uncompress and move the `kubectl-gadget` executable to your `PATH`.

```
$ curl -sL https://github.com/kinvolk/inspektor-gadget/releases/download/v0.2.0/inspektor-gadget-linux-amd64.tar.gz | sudo tar -C /usr/local/bin -xzf - kubectl-gadget
$ kubectl gadget version
```

### Compile from the sources

```
$ git clone https://github.com/kinvolk/inspektor-gadget.git
$ cd inspektor-gadget
$ make kubectl-gadget-linux-amd64
$ sudo cp kubectl-gadget-linux-amd64 /usr/local/bin/kubectl-gadget
$ kubectl gadget version
```

## Installing in the cluster

### Quick installation

```
$ kubectl gadget deploy | kubectl apply -f -
```

This will deploy the gadget DaemonSet along with its RBAC rules.

### Choosing the gadget image

If you wish to install an alternative gadget image, you could use the following commands:

```
$ kubectl gadget deploy --image=docker.io/myfork/gadget:tag | kubectl apply -f -
```

### Hook Mode

Inspektor Gadget needs to detect when containers are started and stopped.
The different supported modes can be set by using the `hook-mode` option:

- `auto`(default): Inspektor Gadget will try to find the best option based on the system it is running on.
- `crio`: Use the [CRIO hooks](https://github.com/containers/podman/blob/v3.0.0-rc3/pkg/hooks/docs/oci-hooks.5.md) support. Inspektor Gadget installs the required hooks in `/usr/share/containers/oci/hooks.d`, be sure that path is part of the `hooks_dir` option on [crio.conf](https://github.com/cri-o/cri-o/blob/v1.20.0/docs/crio.conf.5.md#crioruntime-table). If `hooks_dir` is not declared at all that path is considered by default.
- `podinformer`: Use a Kubernetes controller to get information about new pods. This option is racy and the first events produced by a container could be lost. This mode is selected when `auto` is used and the above modes are not available.
- `nri`: Use the [Node Resource Interface](https://github.com/containerd/nri). It requires containerd v1.5 and it's not considered when `auto` is used.
- `fanotify`: Uses the Linux [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API. It only works with runc.

### Specific Information for Different Platforms

This section explains the additional steps that are required to run Inspektor
Gadget in some platforms.

#### Minikube

You should create the minikube cluster in different ways according to the gadget
you want to use. If you want to use traceloop or the network policy advisor you
should use the VM driver. Otherwise the docker driver is the recommented option.


##### Using a VM driver

This option uses a VM driver (like Virtualbox or kvm2) and a custom minikube
image that contains a more recent kernel version (5.4.40) and some features
enabled to make eBPF programs work there. More details are available
[here](https://github.com/kinvolk/cloud-native-bpf-workshop/blob/master/minikube.md#our-branch).

```
$ wget https://cloud-native-bpf-workshop-public.s3.eu-central-1.amazonaws.com/minikube.iso
$ minikube start --driver=kvm2 --iso-url=file://$(pwd)/minikube.iso

# Deploy Inspektor Gadget in the cluster as described above
```

##### Using the docker driver

This option uses docker and hence the kernel of the host.

```
$ minikube start --driver=docker

# Deploy Inspektor Gadget in the cluster as described above
```

## Uninstalling from the cluster

The following command will remove all the resources created by Inspektor
Gadget from the cluster:

```
$ kubectl gadget undeploy
```
