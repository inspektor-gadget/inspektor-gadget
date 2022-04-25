---
title: 'Using trace open'
weight: 10
---

The trace open gadget watches files that programs in pods open.

Here we deploy a small demo pod "mypod":

```bash
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'while /bin/true ; do whoami ; sleep 3 ; done'
```

Using the trace open gadget, we can see which processes open what files.
We can simply filter for the pod "mypod" and omit specifying the node,
thus traceing on all nodes for pod "mypod":

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
