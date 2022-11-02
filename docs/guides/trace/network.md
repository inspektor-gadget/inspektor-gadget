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
NODE             NAMESPACE        POD                            TYPE      PROTO  PORT    REMOTE
minikube         demo             shell                          OUTGOING  udp    53      svc kube-system/kube-dns
minikube         demo             shell                          OUTGOING  tcp    80      endpoint 1.1.1.1
```

### With local-gadget

* Start local-gadget:

```bash
$ sudo ./local-gadget --runtimes=docker
» create network-graph trace1 --container-selector demo
State: Started
» stream trace1 -f
```

* Generate some network traffic:

```bash
> $ docker run --name demo -ti --rm busybox
> / # for i in `seq 5` ; do wget http://1.1.1.1.nip.io/ ; done
```

* Observe the results:

```json
{"type":"debug","message":"tracer attached","node":"local","namespace":"default","pod":"demo"}
{"type":"normal","namespace":"default","pod":"demo","pktType":"OUTGOING","proto":"tcp","addr":"1.1.1.1","port":80}
{"type":"normal","namespace":"default","pod":"demo","pktType":"OUTGOING","proto":"udp","addr":"192.168.0.1","port":53}
```
