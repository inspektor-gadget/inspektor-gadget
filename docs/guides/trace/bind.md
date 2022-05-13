---
title: 'Using trace bind'
weight: 20
description: >
  Trace the kernel functions performing socket binding.
---

![Screencast of the trace bind gadget](bind.gif)

The trace bind gadget is used to stream socket binding syscalls.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run test-pod --image busybox:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace bind
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             PROTO  ADDR             PORT   OPTS   IF
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
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             PROTO  ADDR             PORT   OPTS   IF
minikube         default          test-pod         test-pod         58208  nc               IP     ::               4242   .R...  0
```

This line corresponds to the socket binding operation initiated by `nc`.

## Restricting output to certain PID, ports or succeeded and failed port bindings

With the following options, you can restrict the output:

* `--pid` only prints events where socket binding is done by the given PID.
* `-P/--ports` only prints events where these ports are used for socket bindings.
* `-i/--ignore-errors` only prints events where the bind succeeded.

So, this command will print all (*i.e.* succeeded and failed) attempts to bind a socket on port 4242 or 4343 by PID 42:

```bash
$ kubectl gadget trace bind -i=false --pid 42 -P=4242,4343
```

## Only print some information

You can customize the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command of the process which sent a signal:

```bash
$ kubectl gadget trace bind -o custom-columns=pid,comm
PID    COMM
61198  nc
```

The following command is the same as default printing:

```bash
$ kubectl gadget trace bind -o custom-columns=node,namespace,container,pod,pid,proto,addr,port,opts,if
NODE             NAMESPACE        CONTAINER        POD              PID    PROTO  ADDR             PORT   OPTS   IF
minikube         default          test-pod         test-pod         61985  IP     ::               4242   .R...  0
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget trace bind -o json
{"type":"normal","node":"minikube","namespace":"default","pod":"test-pod","container":"test-pod","pid":62232,"comm":"nc","proto":"IP","addr":"::","port":4343,"opts":".R...","if":"0","mountnsid":4026532579}
# You can use jq to make the output easier to read:
$ kubectl gadget trace bind -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "default",
  "pod": "test-pod",
  "container": "test-pod",
  "pid": 62232,
  "comm": "nc",
  "proto": "IP",
  "addr": "::",
  "port": 4343,
  "opts": ".R...",
  "if": "0",
  "mountnsid": 4026532579
}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod test-pod
pod "test-pod" deleted
```
