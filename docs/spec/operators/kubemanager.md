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

### `containername` / `k8s-containername`

Show only data from containers with that name

Fully qualified name: `operator.KubeManager.containername` or `operator.KubeManager.k8s-containername`

### `podname` / `k8s-podname`

Show only data from pods with that name

Fully qualified name: `operator.KubeManager.podname` or `operator.KubeManager.k8s-podname`

### `selector` / `k8s-selector`

Kubernetes Labels selector to filter on. Only '=' is supported (e.g. key1=value1,key2=value2)

Fully qualified name: `operator.KubeManager.selector` / `operator.KubeManager.k8s-selector`

### `namespace` / `k8s-namespace`

Show only data from pods in a given namespace

Fully qualified name: `operator.KubeManager.namespace` / `operator.KubeManager.k8s-namespace`

### `all-namespaces`

Show data from pods in all namespaces

Fully qualified name: `operator.KubeManager.all-namespaces`

### `runtime-containername`

Show data only from containers with the runtime-assigned name (not the name defined in the pod spec)

Fully qualified name: `operator.KubeManager.runtime-containername`