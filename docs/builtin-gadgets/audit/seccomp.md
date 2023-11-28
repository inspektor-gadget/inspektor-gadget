---
title: 'Using audit seccomp'
weight: 20
description: >
  Trace syscalls that seccomp sent to the audit log.
---

The audit seccomp gadget provides a stream of events with syscalls that had
their seccomp filters generating an audit log. An audit log can be generated in
one of these two conditions:

* The Seccomp profile has the flag `SECCOMP_FILTER_FLAG_LOG` (currently
  [unsupported by runc](https://github.com/opencontainers/runc/pull/3390)) and
  returns any action other than `SECCOMP_RET_ALLOW`.
* The Seccomp profile does not have the flag `SECCOMP_FILTER_FLAG_LOG` but
  returns `SCMP_ACT_LOG` or `SCMP_ACT_KILL*`.

### On Kubernetes

* Install the Seccomp Operator.

* Install a SeccompProfile that log the `mkdir` and `unshare` syscalls.

```yaml
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  name: log
  annotations:
    description: "Log some syscalls"
spec:
  defaultAction: SCMP_ACT_ALLOW
  syscalls:
  - action: SCMP_ACT_KILL
    names:
    - unshare
  - action: SCMP_ACT_LOG
    names:
    - mkdir
```

* Start a pod with that SeccompProfile.

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: mypod
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/default/log.json
  restartPolicy: Never
  containers:
  - name: container1
    image: busybox
    command: ["sh"]
    args: ["-c", "sleep infinity"]
```

* Start the audit-seccomp gadget.

```bash
$ kubectl gadget audit seccomp -o columns=k8s.namespace,k8s.pod,syscall,code
K8S.NAMESPACE    K8S.POD          SYSCALL          CODE
```

* In another terminal, execute the aforementioned syscalls in the pod.

```bash
$ kubectl exec -ti  mypod -- /bin/sh
/ # mkdir /tmp/dir42 ; unshare -i
Bad system call (core dumped)
```

* Observe the syscalls logged by seccomp in the first terminal.

```
K8S.NAMESPACE    K8S.POD          SYSCALL          CODE
default          mypod            mkdir            log
default          mypod            unshare          kill_thread
```

### With `ig`

* Prepare a Seccomp Profile.

```json
{
  "defaultAction": "SCMP_ACT_ALLOW",
  "syscalls": [
    {
      "action": "SCMP_ACT_KILL",
      "names": [
        "unshare"
      ]
    }
  ]
}
```

* Start the audit-seccomp gadget.

```bash
$ sudo ig audit seccomp -r docker
RUNTIME.CONTAINERNAME                              PID        COMM             SYSCALL     CODE
```

* In another terminal, start a container and run unshare:

```bash
$ docker run -ti --rm --security-opt seccomp=profile.json ubuntu
# unshare -i
Bad system call (core dumped)
```

* Observe the syscalls logged by seccomp in the first terminal.

```bash
$ sudo ig audit seccomp -r docker
RUNTIME.CONTAINERNAME                              PID        COMM             SYSCALL     CODE
eager_mclean                                       231712     unshare          unshare     kill_thread
```
