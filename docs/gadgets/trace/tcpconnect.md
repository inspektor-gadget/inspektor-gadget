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
K8S.NODE                 K8S.NAMESPACE            K8S.POD                  K8S.CONTAINER            PID        COMM          IP SRC                     DST
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:46779   r/1.1.1.1:80
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:21731   r/1.1.1.1:443
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
K8S.NODE                 K8S.NAMESPACE            K8S.POD                  K8S.CONTAINER            PID        COMM          IP SRC                     DST
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:46779   r/1.1.1.1:80   # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:21731   r/1.1.1.1:443  # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:40676   r/1.1.1.1:80
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:40630   r/1.1.1.1:443
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
K8S.NODE                 K8S.NAMESPACE            K8S.POD                  K8S.CONTAINER            PID        COMM          IP SRC                     DST
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:46779   r/1.1.1.1:80   # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:21731   r/1.1.1.1:443  # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:40676   r/1.1.1.1:80   # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:40630   r/1.1.1.1:443  # (previous output)
minikube-docker          default                  mypod                    mypod                    2011630    wget          4  p/default/mypod:17418   r/1.0.0.1:80
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
$ docker run -it --rm --name test-tcp-connect busybox /bin/sh -c "wget 1.1.1.1"
Connecting to 1.1.1.1 (1.1.1.1:80)
Connecting to 1.1.1.1 (1.1.1.1:443)
wget: note: TLS certificate validation not implemented
saving to 'index.html'
index.html           100% |********************************| 54361  0:00:00 ETA
'index.html' saved
```

The gadget will show the connection and related information to it.

```bash
$ sudo ig trace tcpconnect -c test-tcp-connect
RUNTIME.CONTAINERNAME                      PID        COMM             IP SRC                                        DST
test-tcp-connect                           2021739    wget             4  172.17.0.2:4784                            1.1.1.1:80
test-tcp-connect                           2021739    wget             4  172.17.0.2:14023                           1.1.1.1:443
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
RUNTIME.CONTAINERNAME         PID        COMM             IP SRC                          DST                                  LATENCY```

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
K8S.NODE              K8S.NAMESPACE  K8S.POD            K8S.CONTAINER      PID        COMM            IP SRC                         DST                               LATENCY
minikube-docker       default        myclientpod        myclientpod        2054329    curl            4  p/default/myclientpod:50306 s/default/nginx:80               47.069µs
minikube-docker       default        myclientpod        myclientpod        2054338    curl            4  p/default/myclientpod:53378 s/default/nginx:80              120.017µs
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
K8S.NODE              K8S.NAMESPACE  K8S.POD            K8S.CONTAINER      PID        COMM            IP SRC                         DST                               LATENCY
...
minikube-docker       default        myclientpod        myclientpod        2056697    curl            4  p/default/myclientpod:32415 s/default/nginx:80             7.820966ms
minikube-docker       default        myclientpod        myclientpod        2056832    curl            4  p/default/myclientpod:32927 s/default/nginx:80            64.388825ms
minikube-docker       default        myclientpod        myclientpod        2056905    curl            4  p/default/myclientpod:46811 s/default/nginx:80            39.244112ms
```

#### With `ig`

Start the trace tcpconnect gadget on a first terminal:

```bash
$ sudo ig trace tcpconnect --latency
RUNTIME.CONTAINERNAME         PID        COMM             IP SRC                          DST                                  LATENCY
```

Then, start a container and download a web page:

```bash
$ docker run -ti --rm --cap-add NET_ADMIN --name=netem wbitt/network-multitool -- /bin/bash
# wget 1.1.1.1
```

The first terminal will show the connections created and their latency:

```bash
RUNTIME.CONTAINERNAME         PID        COMM             IP SRC                          DST                                  LATENCY
netem                         2036550    wget             4  172.17.0.2:47250             1.1.1.1:80                       14.149828ms
netem                         2036550    wget             4  172.17.0.2:44734             1.1.1.1:443                      15.025666ms
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
RUNTIME.CONTAINERNAME         PID        COMM             IP SRC                          DST                                  LATENCY
...
netem                         2037935    wget             4  172.17.0.2:38587             1.1.1.1:80                      1.006814808s
...
netem                         2037935    wget             4  172.17.0.2:10469             1.1.1.1:443                     1.010320064s
```
