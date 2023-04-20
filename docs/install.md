---
title: Installation
weight: 10
description: >
  How to install Inspektor Gadget
---

<!-- toc -->
- [Installing kubectl gadget](#installing-kubectl-gadget)
  * [Using krew](#using-krew)
  * [Install a specific release](#install-a-specific-release)
  * [Compile from source](#compile-from-source)
- [Installing in the cluster](#installing-in-the-cluster)
  * [Quick installation](#quick-installation)
  * [Choosing the gadget image](#choosing-the-gadget-image)
  * [Hook Mode](#hook-mode)
  * [Specific Information for Different Platforms](#specific-information-for-different-platforms)
    + [Minikube](#minikube)
- [Uninstalling from the cluster](#uninstalling-from-the-cluster)
- [Version skew policy](#version-skew-policy)
- [Installing `ig`](#installing-ig)
  * [Install a specific release](#install-a-specific-release-1)
  * [Compile from source](#compile-from-source-1)
<!-- /toc -->

Inspektor Gadget is composed of a `kubectl` plugin executed in the user's
system and a DaemonSet deployed in the cluster.

## Installing kubectl gadget

Choose one way to install the Inspektor Gadget `kubectl` plugin.

### Using krew

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl gadget` by executing the following
commands.

```bash
$ kubectl krew install gadget
$ kubectl gadget --help
```

### Install a specific release

Download the asset for a given release and platform from the
[releases page](https://github.com/inspektor-gadget/inspektor-gadget/releases/),
uncompress and move the `kubectl-gadget` executable to your `PATH`.

```bash
$ curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/latest/download/kubectl-gadget-linux-amd64.tar.gz | sudo tar -C /usr/local/bin -xzf - kubectl-gadget
$ kubectl gadget version
```

### Compile from source

To build Inspektor Gadget from source, you'll need to have a Golang version
1.19 or higher installed.

```bash
$ git clone https://github.com/inspektor-gadget/inspektor-gadget.git
$ cd inspektor-gadget
$ make kubectl-gadget-linux-amd64
$ sudo cp kubectl-gadget-linux-amd64 /usr/local/bin/kubectl-gadget
$ kubectl gadget version
```

## Installing in the cluster

### Quick installation

```bash
$ kubectl gadget deploy
```

This will deploy the gadget DaemonSet along with its RBAC rules.

![Screencast of the deploy command](install.gif)

### Choosing the gadget image

If you wish to install an alternative gadget image, you could use the following commands:

```bash
$ kubectl gadget deploy --image=ghcr.io/myfork/inspektor-gadget:tag
```

### Deploy to specific nodes

The `--node-selector` flag accepts a [label
selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors)
that defines the nodes where Inspektor Gadget will be deloyed to:

```bash
# Deploy only to the minikube-m02 node
$ kubectl gadget deploy --node-selector kubernetes.io/hostname=minikube-m02

# Deploy to all nodes but minikube
$ kubectl gadget deploy --node-selector kubernetes.io/hostname!=minikube

# Deploy to minikube and minikube-m03 nodes only
$ kubectl gadget deploy --node-selector 'kubernetes.io/hostname in (minikube, minikube-m03)'
```

### Hook Mode

Inspektor Gadget needs to detect when containers are started and stopped.
The different supported modes can be set by using the `hook-mode` option:

- `auto`(default): Inspektor Gadget will try to find the best option based on
  the system it is running on.
- `crio`: Use the [CRIO
  hooks](https://github.com/containers/podman/blob/v3.4.4/pkg/hooks/docs/oci-hooks.5.md)
  support. Inspektor Gadget installs the required hooks in
  `/etc/containers/oci/hooks.d`, be sure that path is part of the `hooks_dir`
  option on
  [crio.conf](https://github.com/cri-o/cri-o/blob/v1.20.0/docs/crio.conf.5.md#crioruntime-table).
  If `hooks_dir` is not declared at all, that path is considered by default.
- `podinformer`: Use a Kubernetes controller to get information about new pods.
  This option is racy and the first events produced by a container could be
  lost. This mode is selected when `auto` is used and the above modes are not
  available.
- `nri`: Use the [Node Resource Interface](https://github.com/containerd/nri).
  It requires containerd v1.5 and it's not considered when `auto` is used.
- `fanotify`: Uses the Linux
  [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API. It only
  works with runc.

### Specific Information for Different Platforms

This section explains the additional steps that are required to run Inspektor
Gadget in some platforms.

#### Minikube

You can deploy Inspektor Gadget in `minikube`.
We recommend to use the `docker` driver:


```bash
$ minikube start --driver=docker
# Deploy Inspektor Gadget in the cluster as described above
```

But can also use the `kvm` one:

```bash
$ minikube start --driver=kvm
# Deploy Inspektor Gadget in the cluster as described above
```

## Uninstalling from the cluster

The following command will remove all the resources created by Inspektor
Gadget from the cluster:

```bash
$ kubectl gadget undeploy
```

## Version skew policy

Inspektor Gadget requires the kubectl-gadget plugin and the DaemonSet
deployed on the cluster to be the exact same version. Even if this is
possible that different versions work well together, we don't provide
any guarantee in those cases. We'll visit this policy again once we
approach to the v1.0 release.

## Installing `ig`

The [`ig`](ig.md) tool can be built and installed
independently. The result is a single binary (statically linked) that can be
copied to a Kubernetes node or any host to trace its containers.

### Install a specific release

It is possible to download the asset for a given release and platform from the
[releases page](https://github.com/inspektor-gadget/inspektor-gadget/releases/).

For instance, to download the latest release for linux-amd64:

```bash
$ curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/latest/download/ig-linux-amd64.tar.gz | sudo tar -C /usr/local/bin -xzf - ig
$ ig version
```

### Compile from source

`ig` is built using a Docker container relying on [Docker Buildx](https://docs.docker.com/buildx/working-with-buildx), so you don't have to worry
about installing dependencies:

```bash
$ make ig
$ sudo cp ig /usr/local/bin/
```

