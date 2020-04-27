# Inspektor Gadget demo: the "execsnoop" gadget

Pods can be selected by Kubernetes labels. Here we deploy a *myapp* which creates
pods with the `role=demo` label:

```
$ kubectl apply -f Documentation/examples/ds-myapp.yaml
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

$ kubectl gadget execsnoop --label role=demo --node ip-10-0-30-247
PCOMM            PID    PPID   RET ARGS
true             16510  11179    0 /bin/true
date             16511  11179    0 /usr/bin/date
cat              16512  11179    0 /usr/bin/cat /proc/version
sleep            16513  11179    0 /usr/bin/sleep 1
true             16514  11179    0 /bin/true
date             16515  11179    0 /usr/bin/date
cat              16516  11179    0 /usr/bin/cat /proc/version
sleep            16517  11179    0 /usr/bin/sleep 1
true             16520  11179    0 /bin/true
date             16521  11179    0 /usr/bin/date
cat              16522  11179    0 /usr/bin/cat /proc/version
sleep            16523  11179    0 /usr/bin/sleep 1
true             16524  10972    0 /bin/true
date             16525  10972    0 /usr/bin/date
echo             16526  10972    0 /bin/echo sleep-10
sleep            16527  10972    0 /bin/sleep 10
true             16528  11179    0 /bin/true
date             16529  11179    0 /usr/bin/date
cat              16530  11179    0 /usr/bin/cat /proc/version
sleep            16531  11179    0 /usr/bin/sleep 1
^CInterrupted!
```

Processes of both pods are spawned: myapp1 spawns `cat /proc/version` and `sleep 1`,
myapp2 spawns `echo sleep-10` and `sleep 10`, both spawn `true` and `date`.
We can stop to trace again by hitting Ctrl-C.

Finally, we clean up our demo app.

```
$ kubectl delete -f Documentation/examples/ds-myapp.yaml
```
