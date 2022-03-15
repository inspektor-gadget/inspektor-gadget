---
title: 'The "network-graph" gadget'
weight: 10
---

The network-graph gadget monitors the network activity in the specified pods
and record the list of TCP connections and UDP streams.

### On Kubernetes

* Start the gadget:
```
$ kubectl apply -f  pkg/resources/samples/trace-network-graph.yaml
trace.gadget.kinvolk.io/network-graph created
$ kubectl annotate -n gadget trace/network-graph gadget.kinvolk.io/operation=start
trace.gadget.kinvolk.io/network-graph annotated
```

* Generate some network traffic:
```
$ kubectl exec -ti -n demo normal-pod-cx7qk -- wget 1.1.1.1
```

* Observe the results:
```
$ kubectl get -n gadget trace.gadget.kinvolk.io/network-graph -o jsonpath='{.status.output}' | jq .
[
  {
    "namespace": "demo",
    "pod": "normal-pod-cx7qk",
    "pkt_type": "PACKET_OUTGOING",
    "proto": "tcp",
    "ip": "1.1.1.1",
    "port": 443
  },
  {
    "namespace": "demo",
    "pod": "normal-pod-cx7qk",
    "pkt_type": "PACKET_OUTGOING",
    "proto": "tcp",
    "ip": "1.1.1.1",
    "port": 80
  }
]
```

### With local-gadget

* Start local-gadget:
```
$ sudo ./local-gadget
» create network-graph trace1 --container-selector demo
State: Started
```

* Generate some network traffic:
```
$ docker run --name demo -ti --rm busybox 
/ # wget 1.1.1.1
```

* Observe the results:
```
» show trace1
State: Started
[{"namespace":"default","pod":"demo","pkt_type":"PACKET_OUTGOING","proto":"tcp","ip":"1.1.1.1","port":443},{"namespace":"default","pod":"demo","pkt_type":"PACKET_OUTGOING","proto":"tcp","ip":"1.1.1.1","port":80}]
»  
```
