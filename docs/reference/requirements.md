---
title: Requirements
sidebar_position: 210
description: >
  Requirements for running Inspektor Gadget.
---

## Kernel

Kernel requirements are largely determined by the specific eBPF functionality a
Gadget makes use of. The eBPF functionality available to Gadgets depend on the
version and configuration of the kernel running running in the node/machine
where the Gadget is being loaded. Gadgets developed by the Inspektor Gadget
project require at least Linux 5.10 with
[BTF](https://www.kernel.org/doc/html/latest/bpf/btf.html) enabled.

## Kubernetes Platform

| Kubernetes platforms                                   | Support                                                                           |
|--------------------------------------------------------|-----------------------------------------------------------------------------------|
| Minikube                                               | ✔️                                                                                |
| AKS, EKS, GKS                                          | ✔️                                                                                |
| AWS Fargate, Azure Containers instances, GKE Autopilot | ❌ (see [#1320](https://github.com/inspektor-gadget/inspektor-gadget/issues/1320)) |
| OpenShift                                              | ✔️                                                                                |
| Talos                                                  | ✔️                                                                                |

## Container Runtime

| Orchestrator      | Container manager | Container runtime | Support                                                                           |
|-------------------|-------------------|-------------------|-----------------------------------------------------------------------------------|
| docker            | containerd        | runc              | ✔️                                                                                |
| nerdctl           | containerd        | runc              | ✔️                                                                                |
| Kubernetes        | containerd        | runc              | ✔️                                                                                |
| Kubernetes        | containerd        | wasm              | ❌ (see [#1899](https://github.com/inspektor-gadget/inspektor-gadget/issues/1899)) |
| Kubernetes        | containerd        | katacontainers    | ❌                                                                                 |
| Kubernetes        | CRI-O             | runc / crun       | Kubernetes v1.20+ (see [below](#cri-o))                                           |
| Podman (root)     | podman            | runc / crun       | ✔️                                                                                |
| Podman (rootless) | podman            | runc / crun       | Only with Podman API enabled (see [below](#podman-rootless))                      |

### CRI-O

We only support [CRI v1](https://github.com/kubernetes/cri-api/tree/master/pkg/apis/runtime/v1) meaning that
only [CRI-O](https://github.com/cri-o/cri-o) v1.20+ (compatible with Kubernetes v1.20+) is supported.

### Podman (rootless)

We use [Podman API](https://docs.podman.io/en/latest/markdown/podman-system-service.1.html) to trace containers. In case
we want trace rootless containers, we need to ensure that the Podman API is available via socket as:

```bash
$ systemctl start --user podman.socket
# use rootless Podman API socket i.e /run/user/USERID#/podman/podman.sock
$ sudo ig -r podman --podman-socketpath /run/user/$UID/podman/podman.sock list-containers
$ sudo ig -r podman --podman-socketpath /run/user/$UID/podman/podman.sock snapshot process
```
