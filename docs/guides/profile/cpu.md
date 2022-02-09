---
title: 'The "profile" gadget'
weight: 10
---

The profile gadget takes samples of the stack traces.

Here we deploy a small demo pod "random":

```bash
$ kubectl run --restart=Never --image=busybox random -- sh -c 'cat /dev/urandom > /dev/null'
pod/random created
```

Using the profile gadget, we can see the list of stack traces.
The following command filters only for pods named "random", execute the command
and interrupt it after ~30 seconds. The `-K` option is passed to show only the
kernel stack traces.

```bash
$ kubectl gadget profile cpu --podname random -K
Node numbers: 0 = ip-10-0-23-61 1 = ip-10-0-3-62^C
```

After a while press with Ctrl-C to stop trace collection

```bash
^C
Terminating...
[ 0] cat;entry_SYSCALL_64_after_hwframe;do_syscall_64;ksys_read;vfs_read;urandom_read;_copy_to_user;copy_user_enhanced_fast_string;copy_user_enhanced_fast_string 4
[ 0] cat 8
[ 0] cat;entry_SYSCALL_64_after_hwframe;do_syscall_64;ksys_read;vfs_read;urandom_read;_raw_spin_unlock_irqrestore;_raw_spin_unlock_irqrestore 136
```

From the traces above, you can see that the pod is spending CPU time in the
Linux function `urandom_read`.

Finally, we need to clean up our pod:

```bash
$ kubectl delete pod random
```
