---
title: 'Using top tcp'
weight: 20
description: >
  Periodically report TCP activity.
---

The top tcp gadget is used to visualize active TCP connections.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget top tcp
NODE            NAMESPACE       POD             CONTAINER       PID     COMM    IP REMOTE                LOCAL                 SENT    RECV
```

Indeed, it is waiting for TCP connection to occur.
So, open *another terminal* and keep and eye on the first one, `exec` the container and use `wget`:

```bash
$ kubectl exec -ti test-pod -- wget kinvolk.io
```

On *the first terminal*, you should see:

```
NODE            NAMESPACE       POD             CONTAINER       PID     COMM    IP REMOTE                LOCAL                 SENT    RECV
minikube        default         test-pod        test-pod        134110  wget    4  188.114.96.3:443      172.17.0.2:38190      0       2
minikube        default         test-pod        test-pod        134110  wget    4  188.114.96.3:80       172.17.0.2:33286      0       1
```

This line corresponds to the TCP connection initiated by `wget`.

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```
