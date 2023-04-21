---
title: 'Using trace tcpconnlat'
weight: 20
description: >
  Trace TCP connects and show connection latency.
---

The trace tcpconnlat gadget tool traces the kernel function performing active TCP connections (eg,
via a connect() syscall), and shows the latency (time) for the connection as measured locally: the
time from SYN sent to the response packet.

TCP connection latency is a useful performance measure showing the time taken to establish a
connection. This typically involves kernel TCP/IP processing and the network round trip time, and
not application runtime.

trace tcpconnlat measures the time from any connection to the response packet, even if the response
is a RST (port closed).

### On Kubernetes

Start the gadget on a terminal:

```bash
$ kubectl gadget trace tcpconnlat
NODE         NAMESPACE    POD         CONTAINER   PID     COMM   IP SADDR           DADDR           SPORT DPORT LATENCY
```

In another terminal, create a nginx service and a pod to send some http requests:

```bash
$ kubectl create service nodeport nginx --tcp=80:80
$ kubectl create deployment nginx --image=nginx
$ kubectl run -ti --privileged --image wbitt/network-multitool myclientpod -- bash
```

Send some requests to the server:

```bash
# curl nginx
# curl nginx
...
```

The first terminal show all those connections and their latency. In my case both pods are running on
the same node, so it's very low:

```bash
NODE             NAMESPACE        POD              CONTAINER        PID       COMM     IP SADDR           DADDR           SPORT DPORT LATENCY
ubuntu-hirsute   default          myclientpod      myclientpod      363550    curl     4  172.16.118.147  10.109.132.206  47078 80    121µs
ubuntu-hirsute   default          myclientpod      myclientpod      363654    curl     4  172.16.118.147  10.109.132.206  60028 80    116µs
```

Now, let's use the [network emulator](https://wiki.linuxfoundation.org/networking/netem) to
introduce some random delay to the packets on the container interface and send some more requests to
the server again:

```bash
# tc qdisc add dev eth0 root netem delay 50ms 50ms 25%
# curl nginx
# curl nginx
```

Now the latency is a lot higher and has some variance because of the emulation configuration:

```bash
NODE             NAMESPACE        POD              CONTAINER        PID       COMM     IP SADDR           DADDR           SPORT DPORT LATENCY
...
ubuntu-hirsute   default          myclientpod      myclientpod      366034    curl     4  172.16.118.147  10.109.132.206  39486 80    32.584ms
ubuntu-hirsute   default          myclientpod      myclientpod      366036    curl     4  172.16.118.147  10.109.132.206  39488 80    56.375ms
ubuntu-hirsute   default          myclientpod      myclientpod      366040    curl     4  172.16.118.147  10.109.132.206  33490 80    79.54ms
```

### With `ig`

Start the trace tcpconnlat gadget on a first terminal:

```bash
$ sudo ig trace tcpconnlat
CONTAINER                      PID        COMM            IP SADDR           DADDR           SPORT DPORT LATENCY
```

Then, start a container and download a web page:

```bash
$ docker run -ti --rm --cap-add NET_ADMIN --name=netem wbitt/network-multitool -- /bin/bash
# wget 1.1.1.1
```

The first terminal will show the connections created and its latency:

```bash
CONTAINER                      PID        COMM            IP SADDR           DADDR           SPORT DPORT LATENCY
netem                          352449     wget            4  172.17.0.4      1.1.1.1         48668 80    49.543ms
netem                          352449     wget            4  172.17.0.4      1.1.1.1         48986 443   57.295ms
```

In this case, it can be seen that two connections were made by the `curl` command and their latency
was around 50ms for each of them.

Now, let's configure the network emulator to add a delay of one second to all packets in the
container's interface and then download the web page again:

```bash
# tc qdisc add dev eth0 root netem delay 1000ms 10ms 100%
# wget 1.1.1.1
```

In this case the `wget` command takes a way longer to complete the request. We can check that the
latency for those connections is more than one second as expected:

```bash
CONTAINER                      PID        COMM            IP SADDR           DADDR           SPORT DPORT LATENCY
...
netem                          352846     wget            4  172.17.0.4      1.1.1.1         38236 80    1.045217s
netem                          352846     wget            4  172.17.0.4      1.1.1.1         45982 443   1.044178s
```
