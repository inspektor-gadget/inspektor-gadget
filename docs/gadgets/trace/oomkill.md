---
title: 'Using trace oomkill'
weight: 20
description: >
  Trace when OOM killer is triggered and kills a process.
---

The trace oomkill gadget is used to monitor when out-of-memory killer kills a process.

## How to use it?

First, we need to create one pod with limited amount of memory:

```bash
$ kubectl apply -f docs/examples/limited-memory-pod.yaml
namespace/oomkill-demo created
pod/test-pod created
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace oomkill -n oomkill-demo
NODE             NAMESPACE        POD              CONTAINER        KPID   KCOMM            PAGES  TPID             TCOMM
```

The gadget is waiting for the OOM killer to get triggered and kill a process in `oomkill-demo` namespace (alternatively, we could use `-A` and get out-of-memory killer events in all namespaces).

To trigger the OOM killer, in *another terminal*, `exec` a container and run this command to exhaust the memory:

```bash
$ kubectl get pod -n oomkill-demo
NAME       READY   STATUS    RESTARTS   AGE
test-pod   1/1     Running   0          52s
$ kubectl exec -n oomkill-demo -ti test-pod -- tail /dev/zero
command terminated with exit code 137
```

Go back to *the first terminal* and see:

```bash
NODE             NAMESPACE        POD              CONTAINER        KPID   KCOMM            PAGES  TPID             TCOMM
minikube         oomkill-demo     test-pod         test-container   11507  tail             32768  11507            tail
```

The printed lined corresponds to the killing of the `perl` process by the OOM killer.
Here is the full legend of all the fields:

* `KPID`: The PID of the process killed by the OOM killer (KilledPID).
* `KOMM`: The command of the process killed by the OOM killer (KilledCommand).
* `PAGES`: The number of pages the killed process had. A page is 4096 bytes on majority of operating system.
* `TPID`: The PID of the process which triggered the OOM killer (TriggeredPID).
* `TCOMM`: The command of the process which triggered the OOM killer (TriggeredCommand).

The line shown above can also be read like this: "The tail command, with PID 11507, running inside the test-container container, in the test-pod pod, in the oomkill-demo namespace, on the minikube node, was killed by the OOM killer because it allocated 32768 pages. The OOM killer was triggered by tail with PID 11507."

Note that, in this case, the command which was killed by the OOM killer is the same which triggered it, **this is not always the case**.

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete -f docs/examples/limited-memory-pod.yaml
namespace "oomkill-demo" deleted
pod "test-pod" deleted
```
