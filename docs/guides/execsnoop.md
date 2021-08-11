---
title: 'The "execsnoop" gadget'
weight: 10
---

Pods can be selected by Kubernetes labels. Here we deploy a *myapp* which creates pods with the `role=demo` label:

```
$ kubectl apply -f docs/examples/ds-myapp.yaml
daemonset.apps/myapp1-pod created
daemonset.apps/myapp2-pod created

$ kubectl get pod --show-labels -o wide
NAME               READY   STATUS    RESTARTS   AGE     IP           NODE             LABELS
myapp1-pod-4kz56   1/1     Running   0          2m24s   10.2.232.6   ip-10-0-30-247   myapp=app-one,name=myapp1-pod,role=demo
myapp1-pod-qnj4d   1/1     Running   0          2m24s   10.2.249.6   ip-10-0-44-74    myapp=app-one,name=myapp1-pod,role=demo
myapp2-pod-s5kvv   1/1     Running   0          2m24s   10.2.249.7   ip-10-0-44-74    myapp=app-two,name=myapp2-pod,role=demo
myapp2-pod-tnthg   1/1     Running   0          2m24s   10.2.232.5   ip-10-0-30-247   myapp=app-two,name=myapp2-pod,role=demo

```

Using the execsnoop gadget, we can see which new processes are spawned on node
ip-10-0-30-247 where myapp1-pod-4kz56 and myapp2-pod-tnthg are running:

```

$ kubectl gadget execsnoop --selector role=demo --node ip-10-0-30-247
NODE             NAMESPACE        PODNAME          CONTAINERNAME   PCOMM            PID    PPID   RET ARGS
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             155962 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             155963 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              155964 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            155965 155894   0 /usr/bin/sleep 1
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             155970 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             155971 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              155972 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            155973 155894   0 /usr/bin/sleep 1
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             156019 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             156020 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              156021 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            156022 155894   0 /usr/bin/sleep 1
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             156043 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             156044 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              156045 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            156046 155894   0 /usr/bin/sleep 1
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             156060 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             156061 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              156062 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            156063 155894   0 /usr/bin/sleep 1
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      true             156105 155894   0 /bin/true
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      date             156106 155894   0 /usr/bin/date
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      cat              156107 155894   0 /usr/bin/cat /proc/version
ip-10-0-30-247   default          myapp1-pod-qddtm myapp1-pod      sleep            156108 155894   0 /usr/bin/sleep 1
^C
Terminating...
```

Processes of both pods are spawned: myapp1 spawns `cat /proc/version` and `sleep 1`,
myapp2 spawns `echo sleep-10` and `sleep 10`, both spawn `true` and `date`.
We can stop to trace again by hitting Ctrl-C.

Finally, we clean up our demo app.

```
$ kubectl delete -f docs/examples/ds-myapp.yaml
```
