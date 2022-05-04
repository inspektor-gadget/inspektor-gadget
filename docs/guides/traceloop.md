---
title: 'Using traceloop'
weight: 30
description: >
  Get strace-like logs of a pod from the past.
---

## Start traceloop

Traceloop is disabled by default from version 0.4.0. It can be enabled by using:

```bash
$ kubectl gadget traceloop start
```

## Multiplication demo

Let's run a pod to compute an important multiplication:

```bash
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'RANDOM=output ; echo "3*7*2" | bc > /tmp/file-$RANDOM ; cat /tmp/file-$RANDOM'
cat: can't open '/tmp/file-3240': No such file or directory
pod default/mypod terminated (Error)
$ kubectl delete pod mypod
pod "mypod" deleted
```

Oh no! We made a mistake in the shell script: we opened the wrong file. Is the
result lost forever? Let's check with the traceloop gadget:

```bash
$ kubectl gadget traceloop list
NODE              TRACES
ip-10-0-30-247    10.0.30.247_default_mypod
ip-10-0-44-74
ip-10-0-5-181
```

Let's inspect the traceloop log:

```bash
$ kubectl gadget traceloop show 10.0.30.247_default_mypod | grep -E 'write|/tmp/file'
00:00.001792832 cpu#0 pid 14276 [runc:[2:INIT]] write(fd=4, buf=842351188896 "{\"type\":\"procReady\"}", count=20)...
00:00.001808990 cpu#0 pid 14276 [runc:[2:INIT]] ...write() = 20
00:00.068726377 cpu#0 pid 14276 [runc:[2:INIT]] write(fd=3, buf=842351686112 "0", count=1)...
00:00.068741259 cpu#0 pid 14276 [runc:[2:INIT]] ...write() = 1
00:00.070542730 cpu#0 pid 14464 [sh] write(fd=1, buf=37966992 "3*7*2\n", count=6)...
00:00.070552565 cpu#0 pid 14464 [sh] ...write() = 6
00:00.070713699 cpu#0 pid 14465 [sh] open(filename=37967352 "/tmp/file-1889", flags=577, mode=438) = 3
00:00.071188694 cpu#1 pid 14465 [bc] write(fd=1, buf=7415808 "42\n", count=3) = 3
00:00.071546191 cpu#1 pid 14276 [cat] open(filename=140723923041877 "/tmp/file-3240", flags=0, mode=0) = 18446744073709551614
00:00.071566973 cpu#1 pid 14276 [cat] write(fd=2, buf=140723923036928 "cat: can't open '/tmp/file-3240': No such file or directory\n", count=60) = 60
```

Thanks to the `traceloop` gadget, we can recover the result of the
multiplication: 42. And we can understand the mistake in the shell script: the
result was saved in `/tmp/file-1889` but we attempted to open
`/tmp/file-3240`.

We can close this trace now.
```bash
$ kubectl gadget traceloop close 10.0.30.247_default_mypod
closed
```

## Listing files demo

With traceloop, we can strace pods in the past, even after they terminated.

Example: let's list the programs in /bin:
```bash
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'ls -l /bin | grep wget'
-rwxr-xr-x  395 root     root       1120520 Apr  2 04:32 wget
$ kubectl delete pod mypod
pod "mypod" deleted
```

Because of the `grep wget`, we only see one entry. But traceloop can recover other entries:

```bash
$ kubectl gadget traceloop list
NODE              TRACES
ip-10-0-30-247    10.0.30.247_default_mypod
ip-10-0-44-74
ip-10-0-5-181

$ kubectl gadget traceloop show 10.0.30.247_default_mypod | grep /bin/w
00:00.074622185 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20772880 "/bin/wall", statbuf=140723555968544, flag=256) = 0
00:00.075257559 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20776192 "/bin/whois", statbuf=140723555968544, flag=256) = 0
00:00.076278991 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20781952 "/bin/which", statbuf=140723555968544, flag=256) = 0
00:00.077687964 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20791600 "/bin/whoami", statbuf=140723555968544, flag=256) = 0
00:00.078381695 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20797072 "/bin/w", statbuf=140723555968544, flag=256) = 0
00:00.080034442 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20806720 "/bin/wc", statbuf=140723555968544, flag=256) = 0
00:00.080110492 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20807152 "/bin/wget", statbuf=140723555968544, flag=256) = 0
00:00.080376067 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20809168 "/bin/who", statbuf=140723555968544, flag=256) = 0
00:00.081162362 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20815360 "/bin/watchdog", statbuf=140723555968544, flag=256) = 0
00:00.081412726 cpu#0 pid 20994 [ls] newfstatat(dfd=18446744073709551516, filename=20817088 "/bin/watch", statbuf=140723555968544, flag=256) = 0

$ kubectl gadget traceloop close 10.0.30.247_default_mypod
closed
```

## Stop traceloop

We can stop the traceloop gadget now that we're done.

```bash
$ kubectl gadget traceloop stop
```
