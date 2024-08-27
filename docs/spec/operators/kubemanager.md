---
title: KubeManager
---

The KubeManager operator is used when Inspektor Gadget is deployed to Kubernetes
as a DaemonSet. This operator keeps track of the pods running on the node by
talking to the kube-apiserver and to the different container runtimes. This
operator uses the pod informer and/or fanotify mechanisms to detect when
containers are created. This information is used to:
- Update the eBPF maps used to filter events in eBPF by Kubernetes concepts like
  pod and container names, namespace, labels, etc.
- Enrich events with container information (see below).
- Attach networking programs to specific containers according to the filtering
  options passed by the user.

This operator uses the mount or network namespace inode IDs to enrich events
with the following fields:

- k8s
  - node name
  - container name
  - pod name
  - namespace
  - pod labels
  - owner
- runtime
  - runtime name
  - container name
  - container ID
  - container image name
  - container image digest
  - container started time

## Priority

-1

## Instance Parameters

### `containername`

Show only data from containers with that name

Fully qualified name: `operators.KubeManager.containername`

### `podname`

Show only data from pods with that name

Fully qualified name: `operators.KubeManager.podname`

### `selector`

Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2)

Fully qualified name: `operators.KubeManager.selector`

### `namespace`

Show only data from pods in a given namespace

Fully qualified name: `operators.KubeManager.namespace`

### `all-namespaces`

Show data from pods in all namespaces

Fully qualified name: `operators.KubeManager.all-namespaces`
