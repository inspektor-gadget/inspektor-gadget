---
title: 'The "network" gadget'
weight: 10
---

The network gadget monitors the network activity in the specified pods
and records the list of TCP connections and UDP streams.

### On Kubernetes

* Start the gadget:
```bash
$ kubectl gadget trace network -n demo
```

* Generate some network traffic:
```bash
$ kubectl run -ti -n demo --image=busybox --restart=Never shell -- wget 1.1.1.1.nip.io
```

* Observe the results:
```
K8S.NODE         K8S.NAMESPACE    K8S.POD                        TYPE      PROTO  PORT    REMOTE
minikube         demo             shell                          OUTGOING  UDP    53      svc kube-system/kube-dns
minikube         demo             shell                          OUTGOING  TCP    80      endpoint 1.1.1.1
```

### With `ig`

Let's start the gadget in a terminal:

```bash
$ sudo ig trace network -c test-container
RUNTIME.CONTAINERNAME           TYPE      PROTO PORT  REMOTE
```

Run a container that generates TCP and UDP network traffic:

```bash
$ docker run --name test-container -ti --rm busybox /bin/sh -c "wget http://1.1.1.1.nip.io/"
```

The tools will show the network activity:

```bash
$ sudo ig trace network -c test-container
RUNTIME.CONTAINERNAME           TYPE      PROTO PORT  REMOTE
demo                            OUTGOING  UDP   53    192.168.67.1
demo                            OUTGOING  TCP   80    1.1.1.1
```
