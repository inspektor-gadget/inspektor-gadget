---
title: 'The "process-collector" gadget'
weight: 10
---

The process-collector gadget gathers information about running processes.

Let's start this demo by creating a namespace:

```
$ kubectl create ns demo
namespace/demo created
```

There is not any running process in the `demo` namespace now:

```
$ kubectl gadget process-collector -n demo
NAMESPACE    POD    CONTAINER    COMM    PID
```

Create a pod on the `demo` namespace using the `nginx` image:

```
$ kubectl -n demo run mypod --image=nginx
pod/mypod created
```

After the pod is running, we can try to get the list of running processes again:

```
$ kubectl gadget process-collector -n demo
NAMESPACE    POD      CONTAINER    COMM     PID
demo         mypod    mypod        nginx    34270
demo         mypod    mypod        nginx    34308
demo         mypod    mypod        nginx    34309
demo         mypod    mypod        nginx    34310
demo         mypod    mypod        nginx    34311
demo         mypod    mypod        nginx    34312
demo         mypod    mypod        nginx    34313
demo         mypod    mypod        nginx    34314
demo         mypod    mypod        nginx    34315
```

We can see the different `nginx` process started within the container.

Execute an instance of `sleep` on the pod:

```
$ kubectl -n demo exec  mypod -- /bin/sh -c "sleep 1000 &"
```

Now there is an additional `sleep` processes running in `mypod`:

```
$ kubectl gadget process-collector -n demo
NAMESPACE    POD      CONTAINER    COMM     PID
demo         mypod    mypod        nginx    34270
demo         mypod    mypod        nginx    37928
demo         mypod    mypod        nginx    37929
demo         mypod    mypod        nginx    37930
demo         mypod    mypod        nginx    37931
demo         mypod    mypod        nginx    37932
demo         mypod    mypod        nginx    37933
demo         mypod    mypod        nginx    37934
demo         mypod    mypod        nginx    37935
demo         mypod    mypod        sleep    41165
```

We can also get the information in JSON format, by passing the `--json` flag.

```
$ kubectl gadget process-collector -n demo --json
[
  {
    "tgid": 34270,
    "pid": 34270,
    "comm": "nginx",
    "namespace": "demo",
    "pod": "mypod",
    "container": "mypod"
  },
  {
    "tgid": 37928,
    "pid": 37928,
    "comm": "nginx",
    "namespace": "demo",
    "pod": "mypod",
    "container": "mypod"
  },
  ...
]

```

Delete the demo test namespace:

```
$ kubectl delete ns demo
namespace "demo" deleted
```
