---
title: KubeIPResolver
---

The KubeIPResolver operator enriches layer 4 endpoints ([gadget_l4endpoint_t](../../gadget-devel/gadget-ebpf-api.md#struct-gadget_l4endpoint_t))
with pod and service information by adding following fields to the events:

- `k8s`:
  - `kind`: The Kubernetes object kind, which can be either `pod` or `svc`.
  - `labels`: The labels of the Kubernetes object.
  - `name`: The name of the Kubernetes object.
  - `namespace`: The namespace of the Kubernetes object.

Also, endpoints are formatted to use the Kubernetes metadata when available with `<kind>/<namespace>/<name>:<port>`
format e.g `p/default/nginx:80` or `s/default/nginx:80` where `p` stands for pod and `s` stands for service.

The example below shows a request from `mypod` pod to `kube-dns` service in json format:

```json
{
  ...
  "dst": {
    "addr": "10.96.0.10",
    "k8s": {
      "kind": "svc",
      "labels": "k8s-app=kube-dns,kubernetes.io/cluster-service=true,kubernetes.io/name=CoreDNS",
      "name": "kube-dns",
      "namespace": "kube-system"
    },
    "port": 53,
    "proto": "UDP",
    "proto_raw": 17,
    "version": 4
  },
  ...
  "src": {
    "addr": "10.244.0.12",
    "k8s": {
      "kind": "pod",
      "labels": "run=mypod",
      "name": "mypod",
      "namespace": "demo"
    },
    "port": 57066,
    "proto": "UDP",
    "proto_raw": 17,
    "version": 4
  },
  ...
}
```


## Priority

10

## Parameters

None
