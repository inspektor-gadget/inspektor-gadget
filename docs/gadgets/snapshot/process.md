---
title: 'Using snapshot process'
weight: 20
description: >
  Gather information about running processes.
---

![Screencast of snapshot process compared to calling kubectl exec ps](process.gif)

The snapshot process gadget gathers information about running processes.

### On Kubernetes

Let's start this demo by creating a namespace:

```bash
$ kubectl create ns demo
namespace/demo created
```

There is not any running process in the `demo` namespace now:

```bash
$ kubectl gadget snapshot process -n demo
NODE    NAMESPACE    POD    CONTAINER    COMM    PID
```

Create a pod on the `demo` namespace using the `nginx` image:

```bash
$ kubectl -n demo run mypod --image=nginx
pod/mypod created
$ kubectl wait -n demo --for=condition=ready pod/mypod
pod/mypod condition met
```

After the pod is running, we can try to get the list of running processes again:

```bash
$ kubectl gadget snapshot process -n demo
NODE        NAMESPACE    POD      CONTAINER    COMM     PID
minikube    demo         mypod    mypod        nginx    582294
minikube    demo         mypod    mypod        nginx    582333
minikube    demo         mypod    mypod        nginx    582334
minikube    demo         mypod    mypod        nginx    582335
minikube    demo         mypod    mypod        nginx    582336
minikube    demo         mypod    mypod        nginx    582337
minikube    demo         mypod    mypod        nginx    582338
minikube    demo         mypod    mypod        nginx    582339
minikube    demo         mypod    mypod        nginx    582340
```

We can see the different `nginx` process started within the container.

Execute an instance of `sleep` on the pod:

```bash
$ kubectl -n demo exec  mypod -- /bin/sh -c "sleep 1000 &"
```

Now there is an additional `sleep` processes running in `mypod`:

```bash
$ kubectl gadget snapshot process -n demo
NODE        NAMESPACE    POD      CONTAINER    COMM     PID
minikube    demo         mypod    mypod        nginx    582294
minikube    demo         mypod    mypod        nginx    582333
minikube    demo         mypod    mypod        nginx    582334
minikube    demo         mypod    mypod        nginx    582335
minikube    demo         mypod    mypod        nginx    582336
minikube    demo         mypod    mypod        nginx    582337
minikube    demo         mypod    mypod        nginx    582338
minikube    demo         mypod    mypod        nginx    582339
minikube    demo         mypod    mypod        nginx    582340
minikube    demo         mypod    mypod        sleep    584294
```

Delete the demo test namespace:

```bash
$ kubectl delete ns demo
namespace "demo" deleted
```

### With local-gadget

Create a container that runs sleep inside:

```bash
$ docker run --name test-snapshot-process -it --rm busybox /bin/sh -c 'sleep 100'
```

Run the snapshot process gadget, it'll print all process in the container:

```bash
$ sudo ./local-gadget snapshot process -c test-snapshot-process
CONTAINER             COMM  PID
test-snapshot-process sleep 100003
```
