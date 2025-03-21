---
title: Quick Start
sidebar_position: 10
description: Quick start for running Inspektor Gadget.
---

Inspektor Gadget can be used either on a Linux machine or on Kubernetes. It
supports both ephemeral commands and permanent installation.

```mermaid
flowchart TD
W{{Where to run Inspektor Gadget?}}
W -->|Kubernetes| K[How long?]
W -->|Linux system| L[How long?]
L --> |Just one command| ig1>ig run]
L --> |Long running| ig2>ig daemon + gadgetctl]
K --> |Just one command| ku1>kubectl debug node]
K --> |Long running| ku2>kubectl gadget]
```

<!-- markdown-link-check-disable-next-line -->
The following examples use the [trace_open](./gadgets/trace_open) Gadget which shows the files being opened.

### Kubernetes

To use Inspektor Gadget on Kubernetes, choose one of the following methods.

#### Alternative 1: long-running deployment on all worker nodes

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl gadget` by executing the following
commands.

```bash
kubectl krew install gadget
kubectl gadget deploy
kubectl gadget run trace_open:%IG_TAG% -n default -c myapp
```

For more details, check [Installing on Kubernetes](./reference/install-kubernetes.md) and the [run](./reference/run.mdx) command for filtering and exporting.

#### Alternative 2: one-shot command on one worker node

We can use [kubectl node debug](https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/) to run `ig` on a Kubernetes node:

```bash
kubectl debug --profile=sysadmin node/minikube-docker -ti \
        --image=ghcr.io/inspektor-gadget/ig:%IG_TAG% -- \
        ig run trace_open:%IG_TAG% \
        --filter k8s.namespace==default,k8s.containerName==myapp
```

For more information on how to use `ig` without installation on Kubernetes, please refer to the [ig documentation](./reference/ig.md#using-ig-with-kubectl-debug-node).

### Linux

To use Inspektor Gadget on a Linux machine, choose one of the following methods.

#### Alternative 1: download the official ig binary

Install the `ig` binary locally on Linux and run a Gadget:

```bash
IG_ARCH=amd64
IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)

curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - ig

sudo ig run trace_open:%IG_TAG% -c mycontainer
```

For more details, check [Installing on Linux](./reference/install-linux.md) and the [run](./reference/run.mdx) command for filtering and exporting.

#### Alternative 2: run ig in a container

```bash
docker run -ti --rm --privileged -v /:/host --pid=host ghcr.io/inspektor-gadget/ig:%IG_TAG% run trace_open:%IG_TAG% -c mycontainer
```

For more information on how to use `ig` without installation on Linux, please check [Using ig in a container](./reference/ig.md#using-ig-in-a-container).

### MacOS or Windows

It's possible to control an `ig` running in Linux from different operating systems by using the `gadgetctl` binary.

Run the following on a Linux machine to make `ig` available to clients.

```bash
sudo ig daemon --host=tcp://0.0.0.0:1234
```

Download the `gadgetctl` tools for MacOS
([amd64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-amd64-v0.30.0.tar.gz),
[arm64](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-darwin-arm64-v0.30.0.tar.gz)) or [windows](https://github.com/inspektor-gadget/inspektor-gadget/releases/download/v0.30.0/gadgetctl-windows-amd64-v0.30.0.tar.gz) and run the Gadget specifying the IP address of the Linux machine:


```bash
gadgetctl run trace_open:%IG_TAG% --remote-address=tcp://$IP:1234 -c mycontainer
```
