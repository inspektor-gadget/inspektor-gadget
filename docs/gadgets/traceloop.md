---
title: 'Using traceloop'
weight: 30
description: >
  Get strace-like logs of a container from the past.
---

The `traceloop` gadget is used to trace system calls issued by containers.

### On Kubernetes

#### Start traceloop

Traceloop is disabled by default from version 0.4.0. It can be enabled by using:

```bash
$ kubectl gadget traceloop start
```

###### Multiplication demo

Let's run a pod to compute an important multiplication:

```bash
$ kubectl create ns test
$ kubectl run --restart=Never -n test -ti --image=busybox mypod -- sh -c 'RANDOM=output ; echo "3*7*2" | bc > /tmp/file-$RANDOM ; cat /tmp/file-$RANDOM'
cat: can't open '/tmp/file-3240': No such file or directory
pod default/mypod terminated (Error)
$ kubectl delete pod -n test mypod
pod "mypod" deleted
```

Oh no! We made a mistake in the shell script: we opened the wrong file. Is the
result lost forever? Let's check with the traceloop gadget:

```bash
$ kubectl gadget traceloop list
K8S.NODE                                K8S.NAMESPACE                          K8S.POD                                K8S.CONTAINER                          CONTAINERID
minikube                                kube-system                            kube-scheduler-minikube                kube-scheduler                         2b63eb745ce2cf
...
minikube                                test                                   mypod                                  mypod                                  ef6f2d3f44b555
```

Let's inspect the traceloop log:

```bash
$ kubectl gadget traceloop show ef6f2d3f44b555
CPU PID        COMM             NAME                                       PARAMS                                                                                        RET
...
1   337825     sh               write                                      fd=1, buf=34716864 3*7*2
, count=6                                                            6
...
1   337826     sh               open                                       filename=34717192 /tmp/file-24581, flags=577, mode=438                                        3
...
1   337826     sh               execve                                     filename=34717344 /bin/bc, argv=34717176, envp=34717224                                       0
...
1   337826     bc               read                                       fd=0, buf=5355360 3*7*2
, count=4096                                                          6
1   337826     bc               write                                      fd=1, buf=5359456 42
, count=3                                                                3
...
0   337813     cat              open                                       filename=140736754175569 /tmp/file-3240, flags=0, mode=0                                      -2
0   337813     cat              write                                      fd=2, buf=140736754168912 cat: can't open '/tmp/file-3240': No such file or directory
, coun… 60
0   337813     cat              exit_group                                 error_code=1                                                                                  X
```

Thanks to the traceloop gadget, we can recover the result of the
multiplication: 42. And we can understand the mistake in the shell script: the
result was saved in `/tmp/file-24581` but we attempted to open
`/tmp/file-3240`.
Note that, return value of `exit_group()` is `X` as this syscall never returns.
The same applies for `exit()` and `rt_sigreturn()`.

You can now remove the trace associated to this container:

```bash
$ kubectl gadget traceloop delete ef6f2d3f44b555
```

And if you no more need the `traceloop` gadget, you can stop it:

```bash
$ kubectl gadget traceloop stop
```

##### Listing files demo

With traceloop, we can strace pods in the past, even after they terminated.

Example: let's list the programs in /bin:

```bash
$ kubectl run -n test --restart=Never -ti --image=debian mypod -- sh -c 'ls -l /bin | grep mv'
-rwxr-xr-x 1 root root  147080 Sep 24  2020 mv
$ kubectl delete pod mypod
pod "mypod" deleted
```

Because of the `grep mv`, we only see one entry. But traceloop can recover other entries:

```bash
$ kubectl gadget traceloop list
...
minikube                                test                                   mypod                                  mypod                                  9c691a53cd43a0
$ kubectl gadget traceloop show 9c691a53cd43a0
...
1   97851      ls               lgetxattr                                  pathname=140729093707632 /bin/more, name=139950439515987 security.selinux, value=94534240126… -61
1   97851      ls               getxattr                                   pathname=140729093707632 /bin/more, name=94534234714099 system.posix_acl_access, value=0, si… -61
1   97851      ls               statx                                      dfd=4294967196, filename=140729093707632 /bin/vdir, flags=256, mask=606, buffer=140729093707… 0
1   97851      ls               lgetxattr                                  pathname=140729093707632 /bin/vdir, name=139950439515987 security.selinux, value=94534240126… -61
1   97851      ls               getxattr                                   pathname=140729093707632 /bin/vdir, name=94534234714099 system.posix_acl_access, value=0, si… -61
1   97851      ls               statx                                      dfd=4294967196, filename=140729093707632 /bin/rmdir, flags=256, mask=606, buffer=14072909370… 0
1   97851      ls               lgetxattr                                  pathname=140729093707632 /bin/rmdir, name=139950439515987 security.selinux, value=9453424012… -61
1   97851      ls               getxattr                                   pathname=140729093707632 /bin/rmdir, name=94534234714099 system.posix_acl_access, value=0, s… -61
1   97851      ls               statx                                      dfd=4294967196, filename=140729093707632 /bin/tempfile, flags=256, mask=606, buffer=14072909… 0
1   97851      ls               lgetxattr                                  pathname=140729093707632 /bin/tempfile, name=139950439515987 security.selinux, value=9453424… -61
1   97851      ls               getxattr                                   pathname=140729093707632 /bin/tempfile, name=94534234714099 system.posix_acl_access, value=0… -61
1   97851      ls               statx                                      dfd=4294967196, filename=140729093707632 /bin/zfgrep, flags=256, mask=606, buffer=1407290937… 0
1   97851      ls               lgetxattr                                  pathname=140729093707632 /bin/zfgrep, name=139950439515987 security.selinux, value=945342401… -61
1   97851      ls               getxattr                                   pathname=140729093707632 /bin/zfgrep, name=94534234714099 system.posix_acl_access, value=0, … -61
1
...
```

### With `ig`

Start a container in interactive mode:

```bash
$ docker run -it --rm --name test-traceloop busybox /bin/sh
```


Start traceloop in another terminal:

```bash
$ sudo ig traceloop -c test-traceloop
```

Run a command inside the container

```bash
$ docker run -it --rm --name test-traceloop busybox /bin/sh
/ # ls

```

Press Ctrl+C on the gadget terminal, it'll print the systemcalls performed by the container:

```bash
$ sudo ig traceloop -c test-traceloop
Tracing syscalls... Hit Ctrl-C to end
^C
CPU PID        COMM             NAME                                       PARAMS                                                                                        RET
...
6   150829     sh               execve                                     filename=18759352 /bin/ls, argv=18759280, envp=18759296                                       0
6   150829     ls               brk                                        brk=0                                                                                         36…
6   150829     ls               brk                                        brk=36440320                                                                                  36…
...
6   150829     ls               write                                      fd=1, buf=5355360 bin   dev   etc   home  pro… 158
6   150829     ls               exit_group                                 error_code=0                                                                                  ...
```
