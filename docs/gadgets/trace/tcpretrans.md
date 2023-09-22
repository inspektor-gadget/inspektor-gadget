---
title: 'Using trace tcpretrans'
weight: 20
description: >
    Trace TCP retransmissions.
---

The trace tcpretrans gadget traces TCP retransmissions by the kernel.

### On Kubernetes

In terminal 1, start the trace tcpretrans gadget:

```bash
$ kubectl gadget trace tcpretrans
K8S.NODE        K8S.NAMESPACE K8S.POD               K8S.CONTAINER PID     COMM  IP SRC                    DST                   STATE     TCPFLAGS
```

In terminal 2, start a pod and configure the network emulator to drop 25% of the packets. This will cause TCP retransmissions:

```bash
$ kubectl create service nodeport nginx --tcp=80:80
$ kubectl create deployment nginx --image=nginx
$ kubectl run --rm -ti --privileged --image ubuntu shell -- bash
root@shell:/# apt-get update
root@shell:/# apt install -y iproute2 curl
root@shell:/# tc qdisc add dev eth0 root netem drop 25%
root@shell:/# curl nginx
```

The results in terminal 1 will show that some TCP transmissions cause by the dropped packets:

```
K8S.NODE        K8S.NAMESPACE K8S.POD               K8S.CONTAINER PID     COMM  IP SRC                    DST                   STATE     TCPFLAGS
minikube-docker default       shell                 shell         2952537 curl  4  p/default/shell:45742  s/default/nginx:80    FIN_WAIT1 FIN|ACK
minikube-docker default       nginx-8f458dc5b-55b8n nginx         2839908 nginx 4  p/default/nginx-8f458d p/default/shell:45742 LAST_ACK  FIN|ACK
```

### With `ig`

In terminal 1, start the trace tcpretrans gadget:

```bash
$ sudo ig trace tcpretrans -r docker -c netem
CONTAINER  PID   COMM  IP SRC               DST          STATE        TCPFLAGS
```

In terminal 2, start a container, configure the network emulator to drop 25% of the packets, and download a web page:

```bash
$ docker run -ti --rm --cap-add NET_ADMIN --name=netem wbitt/network-multitool -- /bin/bash
# tc qdisc add dev eth0 root netem drop 25%
# wget 1.1.1.1
```

The container needs NET_ADMIN capability to manage network interfaces

The results in terminal 1 will show some TCP transmissions caused by the dropped packets:

```
CONTAINER  PID   COMM  IP SRC               DST          STATE        TCPFLAGS
netem      11612 wget  4  172.17.0.4:53516  1.1.1.1:443  ESTABLISHED  PSH|ACK
```
