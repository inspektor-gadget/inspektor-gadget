---
title: KubeIPResolver
---

The KubeIPResolver operator enriches layer 4 endpoints ([gadget_l4endpoint_t](../../gadget-devel/gadget-ebpf-api.md#struct-gadget_l4endpoint_t))
with pod and service information by adding following fields to the events:

- `k8s`:
  - `kind`: The Kubernetes object kind. One of:
    - `pod`: the IP belongs to a pod.
    - `svc`: the IP belongs to a service's ClusterIP.
    - `host`: the IP is a node's address (`InternalIP`/`ExternalIP`), or the IP
      of a pod running with `hostNetwork: true` (in which case it's really the
      node's IP, shared by the node and possibly other host-network pods, so
      it can't be attributed to that specific pod). Note that kubelet health
      checks (liveness/readiness/startup probes) also originate from the
      node's IP, so they're classified as `host` too.
    - `raw`: the IP could not be resolved to any of the above.
  - `labels`: The labels of the Kubernetes object. Not set for `host`/`raw`.
  - `name`: The name of the Kubernetes object. Not set for `host`/`raw`.
  - `node`: The node name. Set for `host` when the address can be associated
    with a Kubernetes node.
  - `namespace`: The namespace of the Kubernetes object. Not set for `host`/`raw`.

Also, endpoints are formatted to use the Kubernetes metadata when available with `<kind>/<namespace>/<name>:<port>`
format e.g `p/default/nginx:80` or `s/default/nginx:80` where `p` stands for pod and `s` stands for service.
For `host` endpoints, the node name is available in the endpoint metadata when
the address can be matched to a Kubernetes node. For `host` and `raw` endpoints,
there's no namespace/pod name, so the format is `n/<addr>:<port>` (`n` for node) and
`r/<addr>:<port>` (`r` for raw) respectively.

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
