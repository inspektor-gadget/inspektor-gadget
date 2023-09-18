---
title: 'Using top tcp'
weight: 20
description: >
  Periodically report TCP activity.
---

The top tcp gadget is used to visualize active TCP connections.

### On Kubernetes

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top tcp
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID       COMM      IP SRC                   DST                   SENT     RECV
```

Indeed, it is waiting for TCP connection to occur.
So, open *another terminal* and keep and eye on the first one, `exec` the container and use `wget`:

```bash
$ kubectl exec -ti test-pod -- wget 1.1.1.1
```

On *the first terminal*, you should see:

```
K8S.NODE           K8S.NAMESPACE K8S.POD    CONTAINER   PID         COMM       IP SRC                        DST                  SENT       RECV      
minikube-docker    default       test-pod   test-pod    289548      wget       4  p/default/test-pod:47228   r/1.1.1.1:443        296B       15.49KiB  
minikube-docker    default       test-pod   test-pod    289540      wget       4  p/default/test-pod:42604   r/1.1.1.1:80         70B        381B      
```

This line corresponds to the TCP connection initiated by `wget`.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```

### With `ig`

Start a container that runs `nginx` and access it locally:

```bash
$ docker run --rm --name test-top-tcp nginx /bin/sh -c 'nginx; while true; do curl localhost; sleep 1; done'
```

Start the gadget, it'll show the different connections created the localhost:

```bash
$ sudo ig top tcp -c test-top-tcp
RUNTIME.CONTAINERNAME      PID         COMM           IP SRC                               DST                               SENT          RECV
test-top-tcp               2177846     nginx          4  127.0.0.1:80                      127.0.0.1:53130                   238B          73B
test-top-tcp               2178303     curl           4  127.0.0.1:53130                   127.0.0.1:80                      73B           853B
```
