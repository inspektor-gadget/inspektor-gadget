---
title: 'The "oomkill" gadget'
weight: 10
---

The `oomkill` gadget is used to monitor when OOM killer actually kills a process.

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

Indeed, it is waiting for OOM killer to kick in and kills a process in `oomkill-demo` namespace (you can use `-A` to monitor all namespaces and then be sure to not miss any event).
So, in *another terminal*, `exec` a container and run this command to exhaust the memory:

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
minikube         oomkill-demo     test-pod         test-container   11507  tail             32768  11507  tail
```

The printed lined correspond to the killing of `perl` process by the OOM killer.
Here is the full legend of all the fields:

* `KPID`: The PID of the process killed by the OOM killer (KilledPID).
* `KOMM`: The command of the process killed by the OOM killer (KilledCommand).
* `PAGES`: The number of pages the killed process had. A page is 4096 bytes on majority of operating system.
* `TPID`: The PID of the process which triggered the OOM killer (TriggeredPID).
* `TCOMM`: The command of the process which triggered the OOM killer (TriggeredCommand).

So, the above line should be read like this: "Command tail, whom PID is 11507, running inside container test-container, within pod test-pod, in namespace oomkill-demo on minikube node, was killed by the OOM killer because it allocated 32768 pages. The OOM killer was triggered by tail whom pid is 11507."

Note that, in this case, the command which was killed by the OOM killer is the same which triggered it, **this is not always the case**.

## Only print some information

You can restrain the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command of the killed process:

```bash
$ kubectl gadget trace oomkill -A -o custom-columns=kpid,kcomm
KPID   KCOMM
15182  tail
```

The following command is the same as default printing:

```bash
$ kubectl gadget trace oomkill -A -o custom-columns=node,namespace,container,pod,kpid,kcomm,pages,tpid,tcomm
NODE             NAMESPACE        CONTAINER        POD              KPID   KCOMM            PAGES  TPID   TCOMM
minikube         oomkill-demo     test-container   test-pod         17349  tail             32768  17349  tail
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget trace oomkill -A -o json
{"type":"normal","node":"minikube","namespace":"oomkill-demo","pod":"test-pod","container":"test-container","tpid":13416,"tcomm":"tail","kpid":13416,"kcomm":"tail","pages":32768,"mountnsid":4026532588}
# You can use jq to make the output easier to read:
$ kubectl gadget trace oomkill -A -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "oomkill-demo",
  "pod": "test-pod",
  "container": "test-container",
  "tpid": 13416,
  "tcomm": "tail",
  "kpid": 13416,
  "kcomm": "tail",
  "pages": 32768,
  "mountnsid": 4026532588
}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete -f docs/examples/limited-memory-pod.yaml
namespace "oomkill-demo" deleted
pod "test-pod" deleted
```
