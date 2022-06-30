---
title: 'Using profile cpu'
weight: 20
description: >
  Analyze CPU performance by sampling stack traces.
---

The profile cpu gadget takes samples of the stack traces.

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
NODE             NAMESPACE        POD              CONTAINER        COMM             PID    COUNT
minikube         default          random           random           cat              17680   1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        _extract_crng
...
minikube         default          random           random           cat              17680   1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        _extract_crng
```

From the traces above, you can see that the pod is spending CPU time in the
Linux function `urandom_read`.

Instead of waiting, you can use the `--timeout` argument:

```bash
$ kubectl gadget profile cpu --timeout 5 --podname random -K
Capturing stack traces...
Capturing stack traces... Hit Ctrl-C to end.^C
NODE             NAMESPACE        POD              CONTAINER        COMM             PID    COUNT
minikube         default          random           random           cat              17680   1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        _extract_crng
...
minikube         default          random           random           cat              17680   1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        _extract_crng
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
$ kubectl gadget profile cpu --timeout 1 --podname random -o custom-columns=node,namespace,pod,container,comm,pid,count,stack
Capturing stack traces...
NODE             NAMESPACE        POD              CONTAINER        COMM             PID    COUNT
minikube         default          random           random           cat              17680  1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        __lock_text_start
        [unknown]
        [unknown]
...
minikube         default          random           random           cat              17680  1
        entry_SYSCALL_64_after_hwframe
        do_syscall_64
        vfs_read
        ksys_read
        urandom_read_nowarn.isra.0
        __lock_text_start
        [unknown]
        [unknown]
```

You can also use JSON as output:

```bash
$ kubectl gadget profile cpu --podname random -o json > /tmp/output.json; jq < /tmp/output.json
{
  "node": "minikube",
  "namespace": "default",
  "pod": "random",
  "container": "random",
  "comm": "cat",
  "pid": 65969,
  "user_stack": [
    "[unknown]",
    "[unknown]"
  ],
  "kernel_stack": [
    "__lock_text_start",
    "__lock_text_start",
    "urandom_read_nowarn.isra.0",
    "vfs_read",
    "ksys_read",
    "do_syscall_64",
    "entry_SYSCALL_64_after_hwframe"
  ],
  "value": 1
}
...
{
  "node": "minikube",
  "namespace": "default",
  "pod": "random",
  "container": "random",
  "comm": "cat",
  "pid": 65969,
  "user_stack": [
    "[unknown]",
    "[unknown]"
  ],
  "kernel_stack": [
    "__lock_text_start",
    "__lock_text_start",
    "_crng_backtrack_protect",
    "urandom_read_nowarn.isra.0",
    "vfs_read",
    "ksys_read",
    "do_syscall_64",
    "entry_SYSCALL_64_after_hwframe"
  ],
  "value": 1
}
```

Finally, we need to clean up our pod:

```bash
$ kubectl delete pod random
```
