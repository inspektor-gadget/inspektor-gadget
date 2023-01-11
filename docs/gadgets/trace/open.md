---
title: 'Using trace open'
weight: 20
description: >
  Trace open system calls.
---

The trace open gadget streams events related to files opened inside pods.

### On Kubernetes

Here we deploy a small demo pod "mypod":

```bash
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'while /bin/true ; do whoami ; sleep 3 ; done'
```

Using the trace open gadget, we can see which processes open what files.
We can simply filter for the pod "mypod" and omit specifying the node,
thus tracing on all nodes for a pod called "mypod":

```bash
$ kubectl gadget trace open --podname mypod
NODE             NAMESPACE        POD              CONTAINER       PID    COMM               FD ERR PATH
ip-10-0-30-247   default          mypod            mypod           18455  whoami              3   0 /etc/passwd
ip-10-0-30-247   default          mypod            mypod           18521  whoami              3   0 /etc/passwd
ip-10-0-30-247   default          mypod            mypod           18525  whoami              3   0 /etc/passwd
ip-10-0-30-247   default          mypod            mypod           18530  whoami              3   0 /etc/passwd
^
Terminating!
```

Seems the whoami command opens "/etc/passwd" to map the user ID to a user name.
We can leave trace open by hitting Ctrl-C.

Finally, we need to clean up our pod:

```bash
$ kubectl delete pod mypod
```


### With local-gadget

Let's start the gadget in a terminal:

```bash
$ sudo local-gadget trace open -c test-trace-open
CONTAINER                                                  PID        COMM             FD    ERR PATH
```

Run a container that opens some files:

```bash
$ docker run --name test-trace-open -it --rm busybox /bin/sh -c 'while /bin/true ; do whoami ; sleep 3 ; done'
```

The tool will show the different files opened by the container:

```bash
$ sudo local-gadget trace open -c test-trace-open
CONTAINER                                                  PID        COMM             FD    ERR PATH
test-trace-open                                            630417     whoami           3     0   /etc/passwd
test-trace-open                                            630954     whoami           3     0   /etc/passwd
```
