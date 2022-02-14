---
title: 'The "sigsnoop" gadget'
weight: 10
---

The `sigsnoop` gadget is used to trace signal sent system-wide.

## How to use it?

First, we need to create one pod for us to play with:

```bash
$ kubectl run debian --image debian:latest sleep inf
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget sigsnoop
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             SIGNAL    TPID   RET
```

Indeed, it is waiting for signals to be sent.
So, in *an other terminal*, `exec` the container and send one signal:

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

With the following option, you can restrain the output:

* `--pid` only prints events where a signal is sent by the given PID.
* `--signal` only prints events where the given signal is sent.
* `-f/--failed-only` only prints events where signal failed to be delivered.

So, this command will only print failed attempts to send `SIGKILL` by PID `42`:

```bash
$ kubectl gadget -f --pid 42 --signal SIGKILL
```

Note that, with `--signal` you can use the name of the signal (e.g. `SIGKILL`) or its integer value (e.g. 9).

## Only print some information

You can customize the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command of the process which sent a signal:

```bash
$ kubectl gadget sigsnoop -o custom-columns=pid,comm
PID    COMM
131951 sh
```

The following command is the same as default printing:

```bash
$ kubectl gadget sigsnoop -A -o custom-columns=node,namespace,container,pod,pid,comm,signal,tpid,ret
NODE             NAMESPACE        POD              CONTAINER        PID    COMM             SIGNAL    TPID   RET
minikube         default          debian           debian           129484 sh               SIGKILL   129491 0
minikube         default          debian           debian           129484 sh               SIGHUP    129491 0
minikube         default          debian           debian           129484 sh               SIGHUP    129484 0
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget sigsnoop -o json
{"type":"normal","node":"minikube","namespace":"default","pod":"debian","container":"debian","pid":142872,"tpid":142885,"signal":9,"comm":"sh","mountnsid":4026532588}
# You can use jq to make the output easier to read:
$ kubectl gadget sigsnoop -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "default",
  "pod": "debian",
  "container": "debian",
  "pid": 142872,
  "tpid": 142885,
  "signal": 9,
  "comm": "sh",
  "mountnsid": 4026532588
}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod debian
pod "debian" deleted
```
