# Inspektor Gadget demo: the "opensnoop" gadget

The opensnoop gadget watches files that programs in pods open.
Pods can be selected by Kubernetes labels, pod names, namespaces, and nodes.
Here we deploy a small demo pod "mypod":

```
$ kubectl run --restart=Never -ti --image=busybox mypod -- sh -c 'while /bin/true ; do whoami ; sleep 3 ; done'
```

Using the opensnoop gadget, we can see which processes open what files.
We can simply filter for the pod "mypod" and omit specifiying the node,
thus snooping on all nodes for pod "mypod":

```
$ ./inspektor-gadget opensnoop --podname mypod
PID    COMM               FD ERR PATH
18455  whoami              3   0 /etc/passwd
18521  whoami              3   0 /etc/passwd
18525  whoami              3   0 /etc/passwd
18530  whoami              3   0 /etc/passwd
^CInterrupted!
```

Seems the whoami command opens "/etc/passwd" to map the user ID to a user name.
We can leave opensnoop by hitting Ctrl-C.

Finally, we need to clean up our pod:

```
$ kubectl delete pod mypod
```
