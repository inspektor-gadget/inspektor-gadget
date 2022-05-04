---
title: 'Using trace exec'
weight: 20
description: >
  Trace new processes.
---

trace exec traces new processes creation.

Let's deploy an example application that will spawn few new processes:

```bash
$ kubectl apply -f docs/examples/ds-myapp.yaml
daemonset.apps/myapp1-pod created
daemonset.apps/myapp2-pod created

$ kubectl get pod --show-labels -o wide
NAME               READY   STATUS    RESTARTS   AGE     IP           NODE             LABELS
myapp1-pod-2gs5r   1/1     Running   0          2m24s   10.2.232.6   ip-10-0-30-247   myapp=app-one,name=myapp1-pod,role=demo
myapp1-pod-qnj4d   1/1     Running   0          2m24s   10.2.249.6   ip-10-0-44-74    myapp=app-one,name=myapp1-pod,role=demo
myapp2-pod-s5kvv   1/1     Running   0          2m24s   10.2.249.7   ip-10-0-44-74    myapp=app-two,name=myapp2-pod,role=demo
myapp2-pod-mqfxv   1/1     Running   0          2m24s   10.2.232.5   ip-10-0-30-247   myapp=app-two,name=myapp2-pod,role=demo

```

Using the trace exec gadget, we can see which new processes are spawned on node
ip-10-0-30-247 where myapp1-pod-2gs5r and myapp2-pod-mqfxv are running:

```bash
$ kubectl gadget trace exec --selector role=demo --node ip-10-0-30-247
NODE                NAMESPACE        POD              CONTAINER       PCOMM            PID    PPID   RET ARGS
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      date             728770 728166   0 /bin/date
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      cat              728771 728166   0 /bin/cat /proc/version
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      sleep            728772 728166   0 /bin/sleep 1
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      true             728802 728166   0 /bin/true
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      date             728803 728166   0 /bin/date
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      cat              728804 728166   0 /bin/cat /proc/version
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      sleep            728805 728166   0 /bin/sleep 1
ip-10-0-30-247      default          myapp2-pod-mqfxv myapp2-pod      true             728832 728052   0 /bin/true
ip-10-0-30-247      default          myapp2-pod-mqfxv myapp2-pod      date             728833 728052   0 /bin/date
ip-10-0-30-247      default          myapp2-pod-mqfxv myapp2-pod      echo             728834 728052   0 /bin/echo sleep-10
ip-10-0-30-247      default          myapp2-pod-mqfxv myapp2-pod      sleep            728835 728052   0 /bin/sleep 10
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      true             728836 728166   0 /bin/true
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      date             728837 728166   0 /bin/date
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      cat              728838 728166   0 /bin/cat /proc/version
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      sleep            728839 728166   0 /bin/sleep 1
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      true             728880 728166   0 /bin/true
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      date             728881 728166   0 /bin/date
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      cat              728882 728166   0 /bin/cat /proc/version
ip-10-0-30-247      default          myapp1-pod-2gs5r myapp1-pod      sleep            728883 728166   0 /bin/sleep 1
^C
Terminating...
```
Processes of both pods are spawned: myapp1 spawns `cat /proc/version` and `sleep 1`,
myapp2 spawns `echo sleep-10` and `sleep 10`, both spawn `true` and `date`.
We can stop to trace again by hitting Ctrl-C.

Finally, we clean up our demo app.

```bash
$ kubectl delete -f docs/examples/ds-myapp.yaml
```
