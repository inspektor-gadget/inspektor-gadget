---
title: 'Using trace tcpconnect'
weight: 10
---

The tcpconnect gadget traces TCP connect calls.
This will help us to define a restrictive policy for outgoing connections.

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

In our Inspektor Gadget terminal we can now see the logged connection:

```bash
$ kubectl gadget trace tcpconnect --podname mypod
Tracing connect ... Hit Ctrl-C to end
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            DPORT
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          80
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  172.17.0.3       1.1.1.1          443
```

(If the pod was started as part of a deployment, the name of the pod is not known
in advance since random characters will be added as suffix.
In that case, it is still possible to trace the connections. We would just
use `kubectl gadget trace tcpconnect --selector key=value` to filter the pods by
labels instead of names.)

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

Switching to the Inspektor Gadget terminal, we see the same connections again
(but now with a new PID since it's a new pod):

```bash
$ kubectl gadget trace tcpconnect --podname mypod  # (still running in old terminal)
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            DPORT
ip-10-0-30-247   default          mypod            mypod           9386                wget         4  10.2.232.47      1.1.1.1          80  # (previous output)
ip-10-0-30-247   default          mypod            mypod           9386                wget         4  10.2.232.47      1.1.1.1          443 # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547               wget         4  10.2.232.51      1.1.1.1          80
ip-10-0-30-247   default          mypod            mypod           16547               wget         4  10.2.232.51      1.1.1.1          443
```

But what if the pod would connect to other IP addresses which we disallowed?
Let's modify our pod to connect to a different address to verify that the connection fails.

```bash
$ kubectl delete pod mypod
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'wget -q -O /dev/null -T 3 http://1.0.0.1 && echo ok || echo failed'
wget: download timed out
failed
```

Indeed the network policy was applied and we can also see in Inspektor Gadget which
connection the pod wanted to make in the last line. Since connecting to port 80 failed
there is no redirect visible to port 443:

```bash
$ kubectl gadget trace tcpconnect --podname mypod  # (still running in old terminal)
NODE             NAMESPACE        POD              CONTAINER       PID    COMM         IP SADDR            DADDR            DPORT
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  10.2.232.47      1.1.1.1          80  # (previous output)
ip-10-0-30-247   default          mypod            mypod           9386   wget         4  10.2.232.47      1.1.1.1          443 # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          80  # (previous output)
ip-10-0-30-247   default          mypod            mypod           16547  wget         4  10.2.232.51      1.1.1.1          443 # (previous output)
ip-10-0-30-247   default          mypod            mypod           17418  wget         4  10.2.232.50      1.0.0.1          80
```

We created a tailored network policy for our (original) demo pod by observing its connection behavior :)
Finally, we should delete the demo pod and network policy again:

```bash
$ kubectl delete pod mypod
pod "mypod" deleted
$ kubectl delete -f docs/examples/network-policy.yaml
networkpolicy.networking.k8s.io "restrictive-network-policy" deleted
```
