# Inspektor Gadget demo: the "execsnoop" gadget

Pods can be selected by Kubernetes labels:

```
$ kubectl exec -ti bcck8s-shell-nqx5p -- /execsnoop-edge --label myapp=app-one
PCOMM            PID    PPID   RET ARGS
pause            1273   1236     0 /pause
sh               1833   1803     0 /usr/bin/sh -c while /bin/true ; do date ; cat /proc/version ; sleep 1 ; done
true             1974   1833     0 /bin/true
date             1975   1833     0 /usr/bin/date
cat              1976   1833     0 /usr/bin/cat /proc/version
sleep            1977   1833     0 /usr/bin/sleep 1
true             1988   1833     0 /bin/true
date             1989   1833     0 /usr/bin/date
cat              1990   1833     0 /usr/bin/cat /proc/version
sleep            1991   1833     0 /usr/bin/sleep 1
```

We even see early events of pods, including the "pause" container.
