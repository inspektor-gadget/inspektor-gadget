---
title: 'Using trace tcpconnect'
weight: 20
description: >
  Trace connect system calls.
---

The trace tcpconnect gadget traces TCP connect calls.

### On Kubernetes

In this guide, we will use this gadget to define a restrictive policy for outgoing connections.

Before we start a demo pod that connects to a public HTTP server, we already begin to trace
the outgoing connections of our future pod (don't terminate it with Ctrl-C for now).

```bash
$ kubectl gadget trace tcpconnect --podname mypod
```

When we run the pod in a new terminal, we see the output `ok` since the public HTTP server was reached.

```bash
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'wget -q -O /dev/null -T 3 http://1.1.1.1 && echo ok || echo failed'
ok
```

In our trace tcpconnect gadget terminal we can now see the logged connection:

```bash
$ kubectl gadget trace tcpconnect --podname mypod
Tracing connect ... Hit Ctrl-C to end
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            SPORT    DPORT
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          40724    80
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          33728    443
```

If the pod was started as part of a deployment, the name of the pod is not known
in advance since random characters will be added as suffix.
In that case, it is still possible to trace the connections. We would just
use `kubectl gadget trace tcpconnect --selector key=value` to filter the pods by
labels instead of names.

There was a HTTP redirect to HTTPS, so we need to allow both ports for our pod.
Don't terminate it yet, we will have another look later.

Since we now know which network accesses our pod does, we can define and apply a very
restrictive network policy:

```bash
$ cat docs/examples/network-policy.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: restrictive-network-policy
  namespace: default
spec:
  podSelector:
    matchLabels:
      run: mypod
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - ipBlock:
        cidr: 1.1.1.1/32
  egress:
  - to:
    - ipBlock:
        cidr: 1.1.1.1/32
    ports:
    - protocol: TCP
      port: 80
    - protocol: TCP
      port: 443

$ kubectl apply -f docs/examples/network-policy.yaml
networkpolicy.networking.k8s.io/restrictive-network-policy created
```

Let's test if the pod still works as expected:

```bash
$ kubectl delete pod mypod
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'wget -q -O /dev/null -T 3 http://1.1.1.1 && echo ok || echo failed'
ok

```

Switching to the gadget trace tcpconnnect terminal, we see the same connections again
(but now with a new PID since it's a new pod):

```bash
$ kubectl gadget trace tcpconnect --podname mypod  # (still running in old terminal)
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            SPORT    DPORT
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          40724    80   # (previous output)
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          33728    443  # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          40676    80
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          40630    443
```

But what if the pod would connect to other IP addresses which we disallowed?
Let's modify our pod to connect to a different address to verify that the connection fails.

```bash
$ kubectl delete pod mypod
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'wget -q -O /dev/null -T 3 http://1.0.0.1 && echo ok || echo failed'
wget: download timed out
failed
```

Indeed the network policy was applied and we can also see in the gadget output which
connection the pod wanted to make in the last line. Since connecting to port 80 failed
there is no redirect visible to port 443:

```bash
$ kubectl gadget trace tcpconnect --podname mypod  # (still running in old terminal)
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            SPORT    DPORT
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          40724    80   # (previous output)
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          33728    443  # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          40676    80   # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          40630    443  # (previous output)
ip-10-0-30-247   default          mypod            mypod           17418  wget         4  10.2.232.50      1.0.0.1          40688    80
```

We created a tailored network policy for our (original) demo pod by observing its connection behavior :)
Finally, we should delete the demo pod and network policy again:

```bash
$ kubectl delete pod mypod
pod "mypod" deleted
$ kubectl delete -f docs/examples/network-policy.yaml
networkpolicy.networking.k8s.io "restrictive-network-policy" deleted
```

### With `ig`

Start the gadget on a terminal.

```bash
$ sudo ig trace tcpconnect -c test-tcp-connect
```

Then, create a gadget that performs a TCP connection.

```bash
$ docker run -it --rm --name test-tcp-connect busybox /bin/sh -c "wget http://www.example.com"
Connecting to www.example.com (93.184.216.34:80)
saving to 'index.html'
index.html           100% |************************************************************************************************|  1256  0:00:00 ETA
'index.html' saved
```

The gadget will show the connection and related information to it.

```bash
$ sudo ig trace tcpconnect -c test-tcp-connect
CONTAINER        PID     COMM             IP  SADDR            DADDR            SPORT    DPORT
test-tcp-connect 503650  wget             4   172.17.0.3       93.184.216.34    40658    80
```

### Calculating the latency of a connection

This tools provides a `--latency` option to show the latency (time) for the connection as measured
from the TCP client perspective: the time from SYN sent to the response packet.

TCP connection latency is a useful performance measure showing the time taken to establish a
connection. This typically involves kernel TCP/IP processing and the network round trip time, and
not application runtime.

This measures the time from any connection to the response packet, even if the response is a RST
(port closed).

When this option is used, the event is only shown when the server replies or the socket is removed.

#### On Kubernetes

Start the gadget on a terminal:

```bash
$ kubectl gadget trace tcpconnect --latency
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

#### With `ig`

Start the trace tcpconnect gadget on a first terminal:

```bash
$ sudo ig trace tcpconnect --latency
CONTAINER                      PID        COMM            IP SADDR           DADDR           SPORT DPORT LATENCY
```

Then, start a container and download a web page:

```bash
$ docker run -ti --rm --cap-add NET_ADMIN --name=netem wbitt/network-multitool -- /bin/bash
# wget 1.1.1.1
```

The first terminal will show the connections created and their latency:

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

In this case the `wget` command takes way longer to complete the request. We can check that the
latency for those connections is more than one second as expected:

```bash
CONTAINER                      PID        COMM            IP SADDR           DADDR           SPORT DPORT LATENCY
...
netem                          352846     wget            4  172.17.0.4      1.1.1.1         38236 80    1.045217s
netem                          352846     wget            4  172.17.0.4      1.1.1.1         45982 443   1.044178s
```
