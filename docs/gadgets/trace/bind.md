---
title: 'Using trace bind'
weight: 20
description: >
  Trace the kernel functions performing socket binding.
---

![Screencast of the trace bind gadget](bind.gif)

The trace bind gadget is used to stream socket binding syscalls.

### On Kubernetes

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace bind
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID    COMM             PROTO  ADDR             PORT   OPTS   IF
```

Indeed, it is waiting for socket binding to occur.
So, in *another terminal*, `exec` the container and use `nc`:

```bash
$ kubectl exec -ti test-pod -- nc -l -p 4242 -w 1
nc: timeout
command terminated with exit code 1
```

Go back to *the first terminal* and see:

```
K8S.NODE         K8S.NAMESPACE    K8S.POD          K8S.CONTAINER    PID    COMM             PROTO  ADDR             PORT   OPTS   IF
minikube         default          test-pod         test-pod         58208  nc               IP     ::               4242   .R...  0
```

This line corresponds to the socket binding operation initiated by `nc`.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```

### With `ig`

Start the gadget first

```bash
$ sudo ig trace bind -c test-trace-bind
K8S.CONTAINER    PID     COMM             PROTO  ADDR             PORT    OPTS    IF
```

In another terminal, run a container that performs a bind operation

```bash
$ docker run -it --rm --name test-trace-bind busybox /bin/sh -c "nc -l -p 4242"
```

The gadget will print the event on the first terminal:

```bash
$ sudo ig trace bind -c test-trace-bind
K8S.CONTAINER    PID     COMM             PROTO  ADDR             PORT    OPTS    IF
test-trace-bind  380299  nc               TCP    ::               4242    .R...   0
```

### Restricting output to certain PID, ports or succeeded and failed port bindings

With the following options, you can restrict the output:

* `--pid` only prints events where socket binding is done by the given PID.
* `-P/--ports` only prints events where these ports are used for socket bindings.
* `-i/--ignore-errors` only prints events where the bind succeeded.

So, this command will print all (*i.e.* succeeded and failed) attempts to bind a socket on port 4242 or 4343 by PID 42:

```bash
$ kubectl gadget trace bind -i=false --pid 42 -P=4242,4343

$ sudo ig trace bind -i=false --pid 42 -P=4242,4343
```
