---
title: Installation
weight: 10
description: >
  How to install.
---

Inspektor Gadget is composed by a `kubectl` plugin executed in the user's
system and a DaemonSet deployed in the cluster.

## Installing kubectl-gadget

Choose one way to install the Inspektor Gadget `kubectl` plugin.

### Using krew

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl-gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl-gadget` by executing the following
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
$ wget https://github.com/kinvolk/inspektor-gadget/releases/download/v0.2.0/inspektor-gadget-linux-amd64.tar.gz
$ tar xvf inspektor-gadget-linux-amd64.tar.gz
$ sudo cp kubectl-gadget /usr/local/bin/
$ kubectl gadget version
```

### Download from Github Actions artifacts

* Go to the [GitHub Actions page](https://github.com/kinvolk/inspektor-gadget/actions)
* Select one successful build from the desired branch and commit
* Download the artifact for your platform:
  ![Download artifacts](github-actions-download-artifacts.png)
* Finish the installation:

```
$ unzip -p inspektor-gadget-linux-amd64.zip | tar xvzf -
$ sudo cp kubectl-gadget /usr/local/bin/
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

### runc hooks mode

Inspektor Gadget needs to detect when containers are started and stopped.
The different supported modes can be set by using the `runc-hooks-mode` option:

- `auto`(default): Inspektor Gadget will try to find the best option based on the system it is running on.
- `crio`: Use the [CRIO hooks](https://github.com/containers/libpod/blob/master/pkg/hooks/docs/oci-hooks.5.md) support. Inspektor Gadget installs the required hooks in `/etc/containers/oci/hooks.d/`, be sure that path is part of the `hooks_dir` option on [libpod.conf](https://github.com/containers/libpod/blob/master/docs/source/markdown/libpod.conf.5.md#options). If `hooks_dir` is not declared at all that path is considered by default.
- `flatcar_edge`: Use a custom `runc` version shipped with Flatcar Container Linux Edge.
- `podinformer`: Use a K8s controller to get information about new pods. This option is racy and the first events produced by a container could be lost. This mode is selected when `auto` is used and the above modes are not available.
- `ldpreload`: Adds an entry in `/etc/ld.so.preload` to call a custom shared library that looks for `runc` calls and dynamically adds the needed OCI hooks to the cointainer `config.json` specification. Since this feature is highly experimental, it'll not be considered when `auto` is used.
