---
title: 'The "seccomp" gadget'
weight: 10
---

The Seccomp Policy Advisor gadget records syscalls that are issued in a
specified pod, and then uses this information to generate the corresponding
seccomp policy. It can integrate with the [Kubernetes Security Profile
Operator](https://github.com/kubernetes-sigs/security-profiles-operator), 
directly generating the necessary `seccompprofile` resource.

Currently, the Seccomp Policy Advisor can only be used by generating a
Trace CRD that states the pods to trace.

### Basic usage

For this demo, we will use a sample Python workload that uses uwsgi, flask
and nginx. The deployment is split in two pieces, the `basic.yaml` file
that has the infrastructure, and the `unconfined.yaml` file that has the
pod definition, with no seccomp profile applied.

```
$ kubectl apply -f docs/examples/seccomp/basic.yaml
namespace/seccomp-demo created
configmap/app-script created
service/hello-python-service created
$ kubectl apply -f docs/examples/seccomp/unconfined.yaml
pod/hello-python created
```

And trace it with the corresponding `trace-status.yaml` sample CRD, that
looks like this:
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

The Trace resource defines which pods we want to trace and what type of
trace we want to run. **Note that you need to set the correct node name in
the spec of this resource**.

To create a trace, we need to first apply the resource, and then use the
operation field to start tracing:

```
$ kubectl apply -f docs/examples/seccomp/trace-status.yaml
trace.gadget.kinvolk.io/seccomp created
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=start
trace.gadget.kinvolk.io/seccomp annotated
```

After that, we need to interact with the workload, to get it to generate
system calls. In our example, it's a simple webservice, and we can interact
with it by forwarding the service port and then querying the service

```
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
corresponding profile, by setting the operation to `generate`.

```
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=generate
trace.gadget.kinvolk.io/seccomp annotated
```

As the `outputMode` was set to `Status`, the generated policy will be
stored in our CR's status. We can look at it and check out the list of
syscalls that our `curl` call triggered.

```
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

### Capturing all syscalls needed to bring up the pod

That sample policy contains only the syscalls executed for that one single
request that we made. If we want to apply a policy to our pod, we need to
also include all the calls needed to bring the pod up.  To do that, we need
to start the trace before the pod is up, then bring up the pod and generate
traffic.

We can stop the current trace using the `stop` operation, and delete the
current pod, so that we can start a fresh new trace.

```
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=stop
trace.gadget.kinvolk.io/seccomp annotated
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted
```

Now we can `start` a new trace, and then create the pod again.

```
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=start
trace.gadget.kinvolk.io/seccomp annotated
$ kubectl apply -f docs/examples/seccomp/unconfined.yaml
pod/hello-python created
```

Once the pod is up, we can once again generate some traffic, like before.

```
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

And now generate the policy again.
```
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=generate
trace.gadget.kinvolk.io/seccomp annotated
```

This time, the Status field will contain a lot more syscalls, as a lot of
operations need to take place to bring up the pod. 

### Integration with Kubernetes Security Profiles Operator

We can use the output stored in the trace to create the seccomp policy for
our pod. But instead of copying it manually, we can also use the
integration with the [Kubernetes Security Profiles
Operator](https://github.com/kubernetes-sigs/security-profiles-operator).

When this operator is
[installed](https://github.com/kubernetes-sigs/security-profiles-operator/blob/master/installation-usage.md#install-operator)
in the cluster, the seccomp gadget can generate `seccompprofile` resources
that can be used directly by our pods.

To do this, we need to change the `outputMode` field to `ExternalResource` and
the `output` field to the namespace and name of the desired resource. You
can edit the trace file and re-apply it. Our example directory already
includes a modified version of the trace in `trace-external.yaml`:

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
  outputMode: ExternalResource
  output: seccomp-demo/hello-profile
```

**Remember that you need to set the right node name**.

We can apply this modified file, which will change the existing resource.
We'll need to capture the syscalls once again, from the start and then call
`generate` again to get the profile generated:

```
$ kubectl apply -f docs/examples/seccomp/trace-external.yaml
trace.gadget.kinvolk.io/seccomp configured

# Delete the pod and stop the previous trace
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=stop
trace.gadget.kinvolk.io/seccomp annotated

# Start a new trace and create the pod again
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=start
trace.gadget.kinvolk.io/seccomp annotated
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

# Now generate the policy as an external resource
$ kubectl annotate -n gadget trace/seccomp gadget.kinvolk.io/operation=generate
trace.gadget.kinvolk.io/seccomp annotated
$ kubectl get -n seccomp-demo seccompprofile
NAME            STATUS      AGE
hello-profile   Installed   9s
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

```
$ kubectl delete -f docs/examples/seccomp/unconfined.yaml
pod "hello-python" deleted
$ kubectl apply -f docs/examples/seccomp/confined.yaml
pod/hello-python created
```

Our workload is now running with the seccomp profile. We can verify that
it's running correctly by querying it once again like before:

```
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

```
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
used by deleting the `seccomp-demo` namespace and the trace resource.

```
$ kubectl delete ns seccomp-demo 
namespace "seccomp-demo" deleted
$ kubectl delete -f docs/examples/seccomp/trace-external.yaml
trace.gadget.kinvolk.io "seccomp" deleted
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
