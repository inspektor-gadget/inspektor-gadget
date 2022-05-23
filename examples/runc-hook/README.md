# Example with the runcfanotify package

This example uses the runcfanotify package
("github.com/kinvolk/inspektor-gadget/pkg/runcfanotify") in order to:

1. receive notifications when a container starts (including its
   [configuration](https://github.com/opencontainers/runtime-spec/blob/main/config.md))
   or terminates
2. execute PreStart and PostStop hooks.

This is not adding the hooks in the container
[configuration](https://github.com/opencontainers/runtime-spec/blob/main/config.md)
but the API works in similar way, so programs designed to be [PreStart or
PostStop OCI
hooks](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks)
can simply be reused here without changes. For instance:

* the commands are executed in the host namespaces
* the commands receive a synthesised [OCI
  State](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state)
over stdin.

This uses a DaemonSet: each pod will only monitor containers locally and there
is no network communication.

To deploy the DaemonSet:
```
$ make install
```

Start a new pod:
```
$ kubectl run -ti --rm --image busybox shell1 -- sh
```

Notice the logs:
```
$ kubectl logs -n runc-hook runc-hook-c9nsf
Container added: 27e08a048becd153a3a73447dfb9dd241079a9f5d24fb2eab768289e06ee73ff pid 417824
{"ociVersion":"1.0.2-dev",...}
OCI State in prestart hook:
{"ociVersion":"1.0.2-dev","id":"27e08a048becd153a3a73447dfb9dd241079a9f5d24fb2eab768289e06ee73ff","status":"created","pid":417824,"bundle":"/run/containerd/io.containerd.runtime.v2.task/moby/27e08a048becd153a3a73447dfb9dd241079a9f5d24fb2eab768289e06ee73ff"}
Container added: 5a3ee42edcb5825ebf6d88b7cedfac5cffb89ccce99e528ce6dbd92a159518ef pid 417888
{"ociVersion":"1.0.2-dev",...}
OCI State in prestart hook:
{"ociVersion":"1.0.2-dev","id":"5a3ee42edcb5825ebf6d88b7cedfac5cffb89ccce99e528ce6dbd92a159518ef","status":"created","pid":417888,"bundle":"/run/containerd/io.containerd.runtime.v2.task/moby/5a3ee42edcb5825ebf6d88b7cedfac5cffb89ccce99e528ce6dbd92a159518ef"}
```

There are two containers because Kubernetes starts a "pause" container along with the requested container.

Notice the Kubernetes events:
```
$ kubectl get events
88s         Normal   NewContainerConfig   node         {"ociVersion":"1.0.2-dev",...}
86s         Normal   NewContainerConfig   node         {"ociVersion":"1.0.2-dev",...}
```
