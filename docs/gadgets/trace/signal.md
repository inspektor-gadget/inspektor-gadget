---
title: 'Using trace signal'
weight: 20
description: >
  Trace signals received by processes.
---

The trace signal gadget is used to trace system signals received by the
pods.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run debian --image debian:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace signal
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             SIGNAL    TPID   RET
```

Indeed, it is waiting for signals to be sent.
So, in *another terminal*, `exec` the container and send one signal:

```bash
$ kubectl exec -ti debian -- sh -c 'sleep 3 & kill -kill $!'
```

Go back to *the first terminal* and see:

```
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             SIGNAL    TPID   RET
minikube         default          debian           debian           129484 sh               SIGKILL   129491 0
minikube         default          debian           debian           129484 sh               SIGHUP    129491 0
minikube         default          debian           debian           129484 sh               SIGHUP    129484 0
```

The first line corresponds to `kill` sending signal `SIGKILL` to `sleep`.

You can also use this gadget to trace when processes die with segmentation fault.
In the *other terminal*, `exec` the container with the following:

```bash
$ kubectl exec -ti debian -- bash
# We first need to install python2.
# apt update && apt install -qy python2
# We can now generate a segfault.
# python2.7 -c "exec'()'*7**6"
```

Now, go back to the first terminal and see that `SIGSEGV` was sent to python:

```
minikube         default          debian           debian           142244 python2.7        SIGSEGV   142244 0
```

## Restricting output to certain PID, signals or failed to send the signals

With the following option, you can restrict the output:

* `--pid` only prints events where a signal is sent by the given PID.
* `--signal` only prints events where the given signal is sent.
* `-f/--failed-only` only prints events where signal failed to be delivered.

For example, this command will only print failed attempts to send `SIGKILL` by PID `42`:

```bash
$ kubectl gadget -f --pid 42 --signal SIGKILL
```

Note that, with `--signal` you can use the name of the signal (e.g. `SIGKILL`) or its integer value (e.g. 9).

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod debian
pod "debian" deleted
```
