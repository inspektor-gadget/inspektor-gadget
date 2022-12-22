---
title: 'Using profile cpu'
weight: 20
description: >
  Analyze CPU performance by sampling stack traces.
---

The profile cpu gadget takes samples of the stack traces.

### On Kubernetes

Here we deploy a small demo pod "random":

```bash
$ kubectl run --restart=Never --image=busybox random -- sh -c 'cat /dev/urandom > /dev/null'
pod/random created
```

Using the profile cpu gadget, we can see the list of stack traces.
The following command filters only for pods named "random", execute the command
and interrupt it after ~30 seconds. The `-K` option is passed to show only the
kernel stack traces.

```bash
$ kubectl gadget profile cpu --podname random -K
Capturing stack traces... Hit Ctrl-C to end.^C
```

After a while press with Ctrl-C to stop trace collection

```
NODE             NAMESPACE        POD                            CONTAINER        PID     COMM             COUNT
minikube         default          random                         random           340800  cat              1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        ksys_read
        vfs_read
        urandom_read
        urandom_read_nowarn.isra.0
        extract_crng
        _extract_crng
...
minikube         default          random                         random           340800  cat              9
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        vfs_read
        ksys_read
        urandom_read
        urandom_read_nowarn.isra.0
        copy_user_generic_string
```

From the traces above, you can see that the pod is spending CPU time in the
Linux function `urandom_read`.

Instead of waiting, you can use the `--timeout` argument:

```bash
$ kubectl gadget profile cpu --timeout 5 --podname random -K
Capturing stack traces...
NODE             NAMESPACE        POD                            CONTAINER        PID     COMM             COUNT
minikube         default          random                         random           340800  cat              1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        ksys_read
        vfs_read
        urandom_read
        urandom_read_nowarn.isra.0
        extract_crng
        _extract_crng
...
minikube         default          random                         random           340800  cat              9
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        vfs_read
        ksys_read
        urandom_read
        urandom_read_nowarn.isra.0
        copy_user_generic_string
```

This gadget also supports custom column outputting, for example:

```bash
$ kubectl gadget profile cpu --timeout 1 --podname random -o custom-columns=node,pod
Capturing stack traces...
NODE             POD
minikube         random
...
minikube         random
```

The following command is the same as default printing:

```bash
$ kubectl gadget profile cpu --timeout 1 --podname random -o custom-columns=node,namespace,pod,container,pid,comm,count,stack
Capturing stack traces...
NODE             NAMESPACE        POD                            CONTAINER        PID     COMM             COUNT
minikube         default          random                         random           340800  cat              1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        ksys_read
        urandom_read
        vfs_read
        urandom_read_nowarn.isra.0
        extract_crng
        _extract_crng
        __lock_text_start
        [unknown]
        [unknown]
...
minikube         default          random                         random           340800  cat              1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_read
        ksys_read
        urandom_read
        vfs_read
        urandom_read_nowarn.isra.0
        extract_crng
        _extract_crng
        __lock_text_start
        [unknown]
        [unknown]
```

Finally, we need to clean up our pod:

```bash
$ kubectl delete pod random
```

### With local-gadget

* Generate some kernel load:

```bash
$ docker run -d --rm --name random busybox cat /dev/urandom > /dev/null
```

* Start local-gadget:

```bash
$ sudo ./local-gadget profile cpu -K --containername random --runtimes docker
```

* Observe the results:

```bash
sudo ./local-gadget profile cpu -K --containername random --runtimes docker
Capturing stack traces... Hit Ctrl-C to end.^C
CONTAINER                                                                                    COMM             PID        COUNT
random                                                                                       cat              641045     1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_sendfile64
        do_sendfile
        splice_file_to_pipe
        generic_file_splice_read
        get_random_bytes_user
        chacha_block_generic
        chacha_permute
...
random                                                                                       cat              641045     5
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        __x64_sys_sendfile64
        do_sendfile
        splice_file_to_pipe
        generic_file_splice_read
        get_random_bytes_user
        chacha_block_generic
        chacha_permute
```

* Remove the docker container:

```bash
$ docker stop random
```
