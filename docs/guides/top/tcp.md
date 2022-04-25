---
title: 'Using top tcp'
weight: 10
---

The `top tcp` gadget is used to monitor TCP connections.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top tcp
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             IPv LADDR
    RADDR                                               RX_KB   TX_KB
```

Indeed, it is waiting for TCP connection to occur.
So, open *an other terminal* and keep and eye on the first one, `exec` the container and use `wget`:

```bash
$ kubectl exec -ti test-pod -- wget kinvolk.io
```

On *the first terminal*, you should see:

```
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             IPv LADDR
    RADDR                                               RX_KB   TX_KB
minikube         default          test-pod         test-pod         49447   wget             4   10.244.2.2:45426
    188.114.97.3:443                                    10      0
```

This line correspond to the TCP connection initiated by `wget`.

## Only print some information

You can customize the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command of the process which sent a signal:

```bash
$ kubectl gadget top tcp -o custom-columns=pid,comm
PID     COMM
49447   wget
```

The following command is the same as default printing:

```bash
$ kubectl gadget top tcp -o custom-columns=node,namespace,pod,container,pid,comm,family,saddr,daddr,sent,received
NODE             NAMESPACE        POD              CONTAINER        PID     COMM             IPv LADDR
    RADDR                                               RX_KB   TX_KB
minikube         default          test-pod         test-pod         49447   wget             4   10.244.2.2:45426
    188.114.97.3:443                                    10      0
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget top tcp -o json
[]
[{"node":"minikube","namespace":"default","pod":"test-pod","container":"test-pod","saddr":"10.244.2.2","daddr":"188.114.96.3","mountnsid":4026532438,"pid":51782,"comm":"wget","sport":38338,"dport":443,"family":2,"received":8802}]
[]
# You can use jq to make the output easier to read:
$ kubectl gadget top tcp -o json | jq
[]
[
  {
    "node": "minikube",
    "namespace": "default",
    "pod": "test-pod",
    "container": "test-pod",
    "saddr": "10.244.2.2",
    "daddr": "188.114.96.3",
    "mountnsid": 4026532438,
    "pid": 51782,
    "comm": "wget",
    "sport": 38338,
    "dport": 443,
    "family": 2,
    "received": 8802
  }
]
[]
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```
