---
title: 'Using advise seccomp-profile'
weight: 20
description: >
  Generate seccomp profiles based on recorded syscalls activity.
---

The seccomp profile advisor gadget records syscalls that are issued in a
specified pod, and then uses this information to generate the corresponding
seccomp profile. It can integrate with the [Kubernetes Security Profile
Operator](https://github.com/kubernetes-sigs/security-profiles-operator),
directly generating the necessary `seccompprofile` resource.

### On Kubernetes

#### Basic usage

For this demo, we will use a sample Python workload that uses uwsgi, flask
and nginx. The deployment is split in two pieces, the `basic.yaml` file
that has the infrastructure, and the `unconfined.yaml` file that has the
pod definition, with no seccomp profile applied.

```bash
$ kubectl apply -f docs/examples/seccomp/basic.yaml
namespace/seccomp-demo created
configmap/app-script created
service/hello-python-service created
$ kubectl apply -f docs/examples/seccomp/unconfined.yaml
pod/hello-python created
```

It is now time to monitor system calls made by our pod:

```bash
$ kubectl gadget advise seccomp-profile start -n seccomp-demo -p hello-python
jMzhur2dQjZJxDCI
```

The string we receive is the identifier that we will use to refer to the
running operation when we want to stop it.

While the advisor is running, we need to interact with the workload, to get it to generate
system calls. In our example, it's a simple webservice, and we can interact
with it by forwarding the service port and then querying the service

```bash
$ kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000 &
[1] 23574
Forwarding from 127.0.0.1:8080 -> 80
Forwarding from [::1]:8080 -> 80

$ curl localhost:8080
Handling connection for 8080
Hello World!

$ kill %1
[1]+  Terminated              kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000
```

Once we have captured the syscalls, we can ask the gadget to generate the
corresponding profile, by stopping the operation with the identifier we had
received before.

```bash
$ kubectl gadget advise seccomp-profile stop jMzhur2dQjZJxDCI
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "accept4",
        "close",
        "connect",
        "epoll_ctl",
        "epoll_wait",
        "fstat",
        "getsockname",
        "getsockopt",
        "ioctl",
        "poll",
        "read",
        "recvfrom",
        "setsockopt",
        "socket",
        "stat",
        "wait4",
        "write",
        "writev"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```

#### Capturing all syscalls needed to bring up the pod

That sample policy contains only the syscalls executed for that one single
request that we made. If we want to apply a policy to our pod, we need to
also include all the calls needed to bring the pod up.  To do that, we need
to start the trace before the pod is up, then bring up the pod and generate
traffic.

We can delete the current pod, so that we can start a fresh new trace.

```bash
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted
```

Now we can create a new trace, and then create the pod again.

```bash
$ kubectl gadget advise seccomp-profile start -n seccomp-demo -p hello-python
TAyR9BXes6GU04rG
$ kubectl apply -f docs/examples/seccomp/unconfined.yaml
pod/hello-python created
```

Once the pod is up, we can once again generate some traffic, like before.

```bash
$ kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000 &
[1] 28318
Forwarding from 127.0.0.1:8080 -> 80
Forwarding from [::1]:8080 -> 80

$ curl localhost:8080
Handling connection for 8080
Hello World!

$ kill %1
[1]+  Terminated              kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000
```

And now generate the policy again:

```bash
$ kubectl gadget advise seccomp-profile stop TAyR9BXes6GU04rG
{
	...
}
```

This time, the output field will contain a lot more syscalls, as a lot of
operations need to take place to bring up the pod.

#### Integration with Kubernetes Security Profiles Operator

We can use the output stored in the trace to create the seccomp policy for our
pod. But instead of copying it manually, we can also use the integration with
the [Kubernetes Security Profiles Operator
(SPO)](https://github.com/kubernetes-sigs/security-profiles-operator). Notice
the seccomp gadget uses the seccomp profile API `v1beta1`, so at least SPO
v0.4.0 is required. Check the [SPO
documentation](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md#install-operator)
for details about installation. Once the SPO is installed, the seccomp gadget
can generate `seccompprofile` resources that can be used directly by our pods.

We need to use the `--output-mode` (or simply `-m`) option to create the
`SeccompProfile` resource instead of printing the policy in the terminal
(default behaviour). Consider that using the option `--profile-prefix`,
we can specify the namespace and the prefix-name of the resource:
`namespace/prefix-name`. Notice the namespace is not mandatory.
If the option `--profile-prefix` is not used, the resource will be
automatically named using the pod name, and it will be created in the
trace's namespace (`gadget` if kubectl-gadget CLI was used).

```bash
# Delete the pod.
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted

# Create the pod and start a new trace again
$ kubectl gadget advise seccomp-profile start -m seccomp-profile -n seccomp-demo -p hello-python
TAyR9BXes6GU04rG
$ kubectl apply -f docs/examples/seccomp/unconfined.yaml
pod/hello-python created

# Generate traffic once again
$ kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000 &
[1] 33679
Forwarding from 127.0.0.1:8080 -> 80
Forwarding from [::1]:8080 -> 80
$ curl localhost:8080
Handling connection for 8080
Hello World!
$ kill %1
[1]+  Terminated              kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000

# Now stop the gadget to generate the seccomp profile.
$ kubectl gadget advise seccomp-profile stop TAyR9BXes6GU04rG
$ kubectl get seccompprofile -n gadget
NAME            STATUS      AGE
hello-python    Installed   9s
```

This profile can now be used as the seccomp profile for our pod. To do
that, we need to edit the configuration and replace the `Unconfined`
setting in our profile type, set it to `Localhost`, and add a
`localhostProfile` entry that points to the profile we just generated.

```yaml
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/gadget/hello-python.json
```

We have this change already applied in the `confined.yaml` file. To apply
this change, we need to delete the current pod and create a new one with
the new configuration:

```bash
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted
$ kubectl apply -f docs/examples/seccomp/confined.yaml
pod/hello-python created
```

Our workload is now running with the seccomp profile. We can verify that
it's running correctly by querying it once again like before:

```bash
$ kubectl port-forward service/hello-python-service -n seccomp-demo 8080:6000 &
[1] 41643
$ Forwarding from 127.0.0.1:8080 -> 80
Forwarding from [::1]:8080 -> 80

$ curl localhost:8080
Handling connection for 8080
Hello World!
```

The request is allowed (as expected), but processes that require additional
syscalls will be blocked. For example, if we try to execute a shell in our
pod:

```bash
$ kubectl exec -it -n seccomp-demo hello-python -- /bin/bash
bash: initialize_job_control: getpgrp failed: Success
command terminated with exit code 1
```

We see that the seccomp profile is preventing this execution, and it will
prevent any other execution that requires syscalls that were not part of
the captured calls.

#### Cleanup

Once we're done with the demo, we can delete all the resources that we've
used by deleting the `seccomp-demo` namespace:

```bash
$ kubectl delete ns seccomp-demo
namespace "seccomp-demo" deleted
```

### With local-gadget

The following animation shows a real world example of generating a seccomp
profile for a `nginx` container:

![Screencast of using advise seccomp-profile to generate a seccomp profile for an nginx container](local_gadget_seccomp_profile.gif)

### Troubleshooting

1. If the annotations don't do anything, check that the node field is set
   correctly. You can also look at the `Status` field of the `Trace` for
   other possible errors.

2. If the confined pod fails to start with this error:
   `cannot load seccomp profile "/var/lib/kubelet/seccomp/operator/seccomp-demo/hello-profile.json"`,
   check that the operator is correctly installed and all pods involved are
   running.
