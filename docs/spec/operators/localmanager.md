---
title: LocalManager
---

The LocalManager operator is used by the `ig` binary. This operator keeps track
of the containers on the system talking to the different container runtimes and
using the fanotify mechanism to detect when containers are created. This
information is used to:
- Update the eBPF maps used to filter events in eBPF by container name.
- Enrich events with container information (see below).
- Attach networking programs to specific containers according to the filtering
  options passed by the user.

This operator uses the mount or network namespace inode IDs to enrich events
with the following fields:

- runtime
  - runtime name
  - container name
  - container ID
  - container image name
  - container image digest
  - container started time

It also adds some Kubernetes information gathered from the container runtimes,
but it doesn't talk to the kube-apiserver unless the
[`enrich-with-k8s-apiserver`](#enrich-with-k8s-apiserver) parameter is set.
- k8s
  - container name
  - pod name
  - namespace
  - pod labels
  - owner (only when using `enrich-with-k8s-apiserver`)

## Priority

-1

## Global Parameters

### `runtimes`

Comma-separated list of container runtimes. Supported values are: docker,
containerd, cri-o, podman.

Default: `docker,containerd,cri-o,podman`

### `docker-socketpath`

Docker Engine API Unix socket path

Default: `/run/docker.sock`

### `crio-socketpath`

CRI-O CRI Unix socket path

Default: `/run/crio/crio.sock`

### `podman-socketpath`

Podman Unix socket path

Default: `/run/podman/podman.sock`

### `containerd-socketpath`

Containerd CRI Unix socket path

Default: `/run/containerd/containerd.sock`

### `container-namespace`

Containerd namespace to use

Default: `k8s.io`

### `runtime-protocol`

Container runtime protocol. Supported values are: internal, cri

Using cri will enrich events with the labels of the Kubernetes pod.

Default: `internal`

### `enrich-with-k8s-apiserver`

Connect to the K8s API server to get further K8s enrichment, like the [owner
reference](https://kubernetes.io/docs/concepts/overview/working-with-objects/owners-dependents/).

Default: `false`

## Instance Parameters

### `containername`

Show only data from containers with that name

Fully qualified name: `operators.LocalManager.containername`

### `host`

Show data from both the host and containers

Fully qualified name: `operators.LocalManager.host`

Default: `false`
