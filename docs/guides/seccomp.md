---
title: 'The "seccomp" gadget'
weight: 10
---

The Seccomp Policy Advisor gadget records syscalls that are issued in a
specified pod, and then uses this information to generate the corresponding
seccomp policy. It can integrate with the [Kubernetes Security Profile
Operator](https://github.com/kubernetes-sigs/security-profiles-operator),
directly generating the necessary `seccompprofile` resource.

### Basic usage

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
$ kubectl gadget seccomp-advisor start -n seccomp-demo -p hello-python
jMzhur2dQjZJxDCI
```

After that, we need to interact with the workload, to get it to generate
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
corresponding profile:

```bash
$ kubectl gadget seccomp-advisor stop jMzhur2dQjZJxDCI
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

### Using `kubectl annotate`

You can also interact with this gadget by using `kubectl annotate`.
To keep our example, you will need to use `trace-status.yaml` which content is
the following:

```
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: seccomp
  namespace: gadget
spec:
  node: demo-node
  gadget: seccomp
  filter:
    namespace: seccomp-demo
    podname: hello-python
  runMode: Manual
  outputMode: Status
```

The `namespace` and `node` under the `filter` label correspond to the `-n` and
`-p` arguments we used previously.
**Note that you need to set the correct node name in the spec of this
resource**.

Once you edited the trace, you can now create it and start it:

```bash
$ kubectl apply -f docs/examples/seccomp/trace-status.yaml
trace.gadget.kinvolk.io/seccomp created
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=start
trace.gadget.kinvolk.io/seccomp annotated
```

After that, you can interact with the workload like we did previously:

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

Now, we can use `kubectl annotate` to generate the trace:

```bash
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=generate
trace.gadget.kinvolk.io/seccomp annotated
```

As the `outputMode` was set to `Status`, the generated policy will be stored in
our CR's status. We can look at it and check out the list of syscalls that our
`curl` call triggered.

```bash
$ kubectl get -n gadget trace/seccomp -o custom-columns=Status:.status
Status
map[output:{
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
} state:Started]
```

We can stop the current trace using the `stop` operation, and delete the
current pod, so that we can start a fresh new trace.

```bash
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=stop
trace.gadget.kinvolk.io/seccomp annotated
$ kubectl delete -f docs/examples/seccomp/trace-status.yaml
```

### Capturing all syscalls needed to bring up the pod

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
$ kubectl gadget seccomp-advisor start -n seccomp-demo -p hello-python
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
$ kubectl gadget seccomp-advisor stop TAyR9BXes6GU04rG
{
	...
}
```

This time, the output field will contain a lot more syscalls, as a lot of
operations need to take place to bring up the pod.

### Integration with Kubernetes Security Profiles Operator

We can use the output stored in the trace to create the seccomp policy for
our pod. But instead of copying it manually, we can also use the
integration with the [Kubernetes Security Profiles
Operator](https://github.com/kubernetes-sigs/security-profiles-operator).

To install the operator, use the following commands:

<!--
In our code, we include seccompprofile/v1alpha1, thus we apply from v0.3.0 to
ensure operator.yaml applies on our code.
-->
```bash
$ kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v1.6.0/cert-manager.yaml
$ kubectl --namespace cert-manager wait --for condition=ready pod -l app.kubernetes.io/instance=cert-manager
$ kubectl apply -f https://raw.githubusercontent.com/kubernetes-sigs/security-profiles-operator/v0.3.0/deploy/operator.yaml
```

Once installed, the seccomp gadget can generate `seccompprofile` resources
that can be used directly by our pods.

To do this, we need to use the `--seccomp-profile` option of the command line.

```bash
# Delete the pod.
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted

# Create the pod and start a new trace again
$ kubectl gadget seccomp-advisor start -n seccomp-demo -m seccomp-profile --seccomp-profile-name seccomp-demo/hello-profile -p hello-python
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
$ kubectl gadget seccomp-advisor stop TAyR9BXes6GU04rG
$ kubectl get -n seccomp-demo seccompprofile
NAME            STATUS      AGE
hello-profile   Installed   42s
```

This profile can now be used as the seccomp profile for our pod. To do
that, we need to edit the configuration and replace the `Unconfined`
setting in our profile type, set it to `Localhost`, and add a
`localhostProfile` entry that points to the profile we just generated.

```
spec:
  securityContext:
    seccompProfile:
      type: Localhost
      localhostProfile: operator/seccomp-demo/hello-profile
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
OCI runtime exec failed: exec failed: container_linux.go:380: starting
container process caused: exec: "/bin/bash": stat /bin/bash: operation not
permitted: unknown
command terminated with exit code 126
```

We see that the seccomp profile is preventing this execution, and it will
prevent any other execution that requires syscalls that were not part of
the captured calls.

### Cleanup

Once we're done with the demo, we can delete all the resources that we've
used by deleting the `seccomp-demo` namespace:

```bash
$ kubectl delete ns seccomp-demo
namespace "seccomp-demo" deleted
```

### Troubleshooting

1. If the annotations don't do anything, check that the node field is set
   correctly. You can also look at the `Status` field of the `Trace` for
   other possible errors.

2. If applying the policy causes the pod not to start, check that you're
   setting `AllowPrivilegeEscalation=false` in the container's security
   context, as having privilege escalation enabled doesn't work well with
   seccomp. See [#267](https://github.com/kinvolk/inspektor-gadget/issues/267)
   for more information.

3. If the confined pod fails to start with this error:
   `cannot load seccomp profile "/var/lib/kubelet/seccomp/operator/seccomp-demo/hello-profile.json"`,
   check that the operator is correctly installed and all pods involved are
   running.
