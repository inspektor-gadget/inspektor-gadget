# Inspektor Gadget demo: the "profile" gadget

The profile gadget takes samples of the stack traces.
Pods can be selected by Kubernetes labels, pod names, namespaces, and nodes.
Here we deploy a small demo pod "random":

```
$ kubectl run --restart=Never --image=busybox random -- sh -c 'cat /dev/urandom > /dev/null'
```

Using the profile gadget, we can see the list of stack traces.
The following command filter only for pods named "random", execute the command
and interrupt it after ~30 seconds. The `-K` option is passed to show only the
kernel stack traces.

```
$ ./inspektor-gadget profile --namespace default --podname random -K
Node numbers: 0 = ip-10-0-23-61 1 = ip-10-0-3-62^C
[...] # Output manually trimmed
[ 0] cat;entry_SYSCALL_64_after_hwframe;do_syscall_64;ksys_read;vfs_read;urandom_read;_copy_to_user;copy_user_enhanced_fast_string;copy_user_enhanced_fast_string 4
[ 0] cat 8
[ 0] cat;entry_SYSCALL_64_after_hwframe;do_syscall_64;ksys_read;vfs_read;urandom_read;_raw_spin_unlock_irqrestore;_raw_spin_unlock_irqrestore 136
```

From the traces above, you can see that the pod is spending CPU time in the
Linux function `urandom_read`.

Finally, we need to clean up our pod:

```
$ kubectl delete pod random
```
