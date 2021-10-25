---
title: 'The "dns" gadget'
weight: 10
---

The dns gadget prints information about DNS requests performed by the different
pods.

Create a `demo` namespace:

```
$ kubectl create ns demo
namespace/demo created
```

Start the dns gadget:

```
$ kubectl gadget dns -n demo
POD                            TYPE      NAME
```

Run a pod on a different terminal and perform some DNS requests:

```
$ kubectl -n demo run mypod -it --image=praqma/network-multitool -- /bin/sh
# nslookup www.microsoft.com
# nslookup www.google.com
# nslookup www.amazon.com
```

The requests will be logged by the DNS gadget:

```
POD                            TYPE      NAME
mypod                          OUTGOING  www.microsoft.com.demo.svc.cluster.local.
mypod                          OUTGOING  www.microsoft.com.svc.cluster.local.
mypod                          OUTGOING  www.microsoft.com.cluster.local.
mypod                          OUTGOING  www.microsoft.com.
mypod                          OUTGOING  e13678.dscb.akamaiedge.net.
mypod                          OUTGOING  www.google.com.demo.svc.cluster.local.
mypod                          OUTGOING  www.google.com.svc.cluster.local.
mypod                          OUTGOING  www.google.com.cluster.local.
mypod                          OUTGOING  www.google.com.
mypod                          OUTGOING  www.google.com.
mypod                          OUTGOING  www.amazon.com.demo.svc.cluster.local.
mypod                          OUTGOING  www.amazon.com.svc.cluster.local.
mypod                          OUTGOING  www.amazon.com.cluster.local.
mypod                          OUTGOING  www.amazon.com.
mypod                          OUTGOING  www-amazon-com.customer.fastly.net.
```

Delete the demo test namespace:

```
$ kubectl delete ns demo
namespace "demo" deleted
```
