---
title: 'Inspektor Gadget demo: the "tcptop" gadget'
weight: 10
---

The tcptop gadget allows us to see active TCP connections.
Let's start a pod that fetches a website every 3 seconds.

```
$ kubectl run --restart=Never --image=busybox mypod -- sh -c 'while /bin/true ; do wget -O - https://kinvolk.io ; sleep 3 ; done'
$ kubectl get pod -o wide
NAME    READY   STATUS    RESTARTS   AGE     IP            NODE             NOMINATED NODE   READINESS GATES
mypod   1/1     Running   0          2m45s   10.2.232.15   ip-10-0-30-247   <none>           <none>
```

Now we use Inspektor Gadget to show us the TCP connections. Every 3 seconds we
can see the website download done by `wget`.

```
$ kubectl gadget tcptop --node ip-10-0-30-247 --namespace default --podname mypod

12:36:41 loadavg: 1.41 1.58 1.11 5/381 690

PID    COMM         LADDR                 RADDR                  RX_KB  TX_KB
5762   5762         10.2.232.15:54326     104.27.186.120:443        16      0
```

We can leave the monitoring with Ctrl-C.
Finally, we should delete the demo pod again:

```
$ kubectl delete pod mypod
pod "mypod" deleted
```
