---
title: 'Using trace signal'
weight: 20
description: >
  Trace signals received by processes.
---

The trace signal gadget is used to trace system signals received by the
pods.

### On Kubernetes

First, we need to create one pod for us to play with:

```bash
$ kubectl run debian --image debian:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace signal
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID    COMM             SIGNAL    TPID   RET
```

Indeed, it is waiting for signals to be sent.
So, in *another terminal*, `exec` the container and send one signal:

```bash
$ kubectl exec -ti debian -- sh -c 'sleep 3 & kill -kill $!'
```

Go back to *the first terminal* and see:

```
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID    COMM             SIGNAL    TPID   RET
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

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod debian
pod "debian" deleted
```

### With `ig`

Start the gadget on a terminal.

```bash
$ sudo ig trace signal -c test-trace-signal
```

Run a container and run sleep in the background, then will it:

```bash
$ docker run -it --rm --name test-trace-signal busybox /bin/sh
/ # sleep 100 &
/ # echo $!
7
/ # kill -kill $!
/ # exit
```

The gadget will show that sh killed a process.

```bash
$ sudo ig trace signal -c test-trace-signal
RUNTIME.CONTAINERNAME      PID        COMM          SIGNAL      TPID       RET
test-trace-signal          11131      sh            SIGKILL     11162      0
test-trace-signal          11131      sh            SIGHUP      11131      0
```

### Restricting output to certain PID, signals or failed to send the signals

With the following option, you can restrict the output:

* `--pid` only prints events where a signal is sent by the given PID.
* `--signal` only prints events where the given signal is sent.
* `-f/--failed-only` only prints events where signal failed to be delivered.
* `-k/--kill-only` only prints events where signal was sent by using kill syscall.

For example, this command will only print failed attempts to send `SIGKILL` by PID `42` which were initiated by calling kill syscall:

```bash
$ kubectl gadget -k -f --pid 42 --signal SIGKILL
```

Note that, with `--signal` you can use the name of the signal (e.g. `SIGKILL`) or its integer value (e.g. 9).
