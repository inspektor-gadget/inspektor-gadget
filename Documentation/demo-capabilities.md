---
title: 'Inspektor Gadget demo: the "capabilities" gadget'
weight: 10
---

The capabilities gadget allows us to see what capability security checks
are triggered by applications running in Kubernetes Pods.

Linux [capabilities](https://linux.die.net/man/7/capabilities) allow for a finer
privilege control because they can give root-like capabilities to processes without
giving them full root access. They can also be taken away from root processes.
If a pod is directly executing programs as root, we can further lock it down
by taking capabilities away. Sometimes we need to add capabilities which
are not there by default. You can see the list of default and available
capabilities [in Docker](https://docs.docker.com/engine/reference/run/#runtime-privilege-and-linux-capabilities).
Specially if our pod is directly run as user instead of root (runAsUser: ID),
we can give some more capabilities (think as partly root) and still take all
unused capabilities to really lock it down.

Here we have a small demo app which logs failures due to lacking capabilities.
Since none of the default capabilities is dropped, we have to find
out what non-default capability we have to add.

```
$ cat Documentation/examples/app-set-priority.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: set-priority
  labels:
    k8s-app: set-priority
spec:
  selector:
    matchLabels:
      name: set-priority
  template:
    metadata:
      labels:
        name: set-priority
    spec:
      containers:
      - name: set-priority
        image: busybox
        command: [ "sh", "-c", "while /bin/true ; do nice -n -20 echo ; sleep 5; done" ]

$ kubectl apply -f Documentation/examples/app-set-priority.yaml
deployment.apps/set-priority created
$ kubectl logs -lname=set-priority
nice: setpriority(-20): Permission denied
nice: setpriority(-20): Permission denied
```

We could see the error messages in the pod's log.
Let's use Inspektor Gadget to watch the capability checks:

```
$ kubectl gadget capabilities --selector name=set-priority
TIME      UID    PID    TID    COMM             CAP  NAME                 AUDIT  INSETID
13:01:54  1      4779   4779   true             6    CAP_SETGID           0      0
13:01:54  1      4779   4779   true             7    CAP_SETUID           0      0
13:01:54  1      4780   4780   nice             6    CAP_SETGID           0      0
13:01:54  1      4780   4780   nice             7    CAP_SETUID           0      0
13:01:54  1      4780   4780   nice             23   CAP_SYS_NICE         0      0
13:01:54  1      4781   4781   sleep            6    CAP_SETGID           0      0
13:01:54  1      4781   4781   sleep            7    CAP_SETUID           0      0
^CInterrupted!
```

We can leave the gadget with Ctrl-C.
In the output we see that the `SYS_NICE` capability got checked when `nice` was run.
We should probably add it to our pod template for `nice` to work. We can also drop
all other capabilites from the default list (see link above) since `nice`
did not use them:

```
$ cat Documentation/examples/app-set-priority-locked-down.yaml 
apiVersion: apps/v1
kind: Deployment
metadata:
  name: set-priority
  labels:
    k8s-app: set-priority
spec:
  selector:
    matchLabels:
      name: set-priority
  template:
    metadata:
      labels:
        name: set-priority
    spec:
      containers:
      - name: set-priority
        image: busybox
        command: [ "sh", "-c", "while /bin/true ; do nice -n -20 echo ; sleep 5; done" ]
        securityContext:
          capabilities:
            add: ["SYS_NICE"]
            drop: [all]

```

At this moment we have to make sure that we are allowed to grant `SYS_NICE` for new pods in the
restricted pod security policy.

```
$ kubectl get psp
NAME                       PRIV    CAPS               SELINUX    RUNASUSER   FSGROUP     SUPGROUP    READONLYROOTFS   VOLUMES
nginx-ingress-controller   false   NET_BIND_SERVICE   RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap,secret
privileged                 true    *                  RunAsAny   RunAsAny    RunAsAny    RunAsAny    false            *
restricted                 false                      RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap, …
```

For privileged pods adding `SYS_NICE` would work, but not for the default pods.
We can change that by edditing the policy.

```
$ kubectl edit psp restricted  # opens the editor to add the below two lines
spec:
  allowPrivilegeEscalation: false
  allowedCapabilities:  # <- add these two
  - SYS_NICE            #    lines here
  …

```

After saving we can verify that we are allowed to add new pods which grant `SYS_NICE`.

```
$ kubectl get psp
NAME                       PRIV    CAPS               SELINUX    RUNASUSER   FSGROUP     SUPGROUP    READONLYROOTFS   VOLUMES
nginx-ingress-controller   false   NET_BIND_SERVICE   RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap,secret
privileged                 true    *                  RunAsAny   RunAsAny    RunAsAny    RunAsAny    false            *
restricted                 false   SYS_NICE           RunAsAny   MustRunAs   MustRunAs   MustRunAs   false            configMap, …
```

Let's verify that our locked-down version works.

```
$ kubectl delete -f Documentation/examples/app-set-priority.yaml 
deployment.apps "set-priority" deleted
$ kubectl apply -f Documentation/examples/app-set-priority-locked-down.yaml 
deployment.apps/set-priority created
$ kubectl logs -lname=set-priority

$ kubectl delete -f Documentation/examples/app-set-priority-locked-down.yaml
```

The logs are clean, so everything works!

By the way, in our Inspekor Gadget terminal we still see the same checks done as expected.
We do not see if they succeed or not (use traceloop to see the syscalls). You may
include a kernel call stack for more context with `--print-stack`.
(If we see additional `SYS_ADMIN` checks we can ignore them since only priviledged pods
have this capability and it's not a default capability.)
