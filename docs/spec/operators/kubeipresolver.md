---
title: KubeIPResolver
---

The KubeIPResolver operator enriches IP addresses with pod and service
information. For instance, in this example the `10.96.0.10` IP is enriched with
namespace, podname, kind, and pod labels.

```json
  "dst": {
    "addr": "10.96.0.10",
    "version": 4,
    "namespace": "kube-system",
    "podname": "kube-dns",
    "kind": "svc",
    "podlabels": {
      "k8s-app": "kube-dns",
      "kubernetes.io/cluster-service": "true",
      "kubernetes.io/name": "CoreDNS"
    }
  }
```

## Parameters

None
