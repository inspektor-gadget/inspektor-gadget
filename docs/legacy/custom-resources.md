---
title: Custom Trace Resource
sidebar_position: 200
description: >
  Basic usage of the Trace resource
---

:::warning

We are currently removing the Trace resource and using a [gRPC
API](../api/grpc.md) instead. Once done, the Trace resource will be
deprecated.

:::

Inspektor Gadget uses a custom `Trace` resource to communicate between the
endpoints and the `gadget` DaemonSet running on the cluster. These
resources are used to control which gadgets run in a given cluster.

This is the basic format of this resource:

```yaml
apiVersion: gadget.kinvolk.io/v1alpha1
kind: Trace
metadata:
  name: trace-name
  namespace: gadget
spec:
  node: node-name
  gadget: gadget-name
  filter:
    namespace: namespace-name
    podname: podname-name
  runMode: Manual
  outputMode: Status
```

Some gadgets work at the node level, while others support specific filters,
like `namespace`, `podname`, `labels`, and so on.

The possible values for `outputMode` also depend on the gadget. The
`seccomp` gadget, for example, can create seccomp policies as an external
resource when `ExternalResource` is selected. If `outputMode` is set to
`Status`, the output of the trace will be stored in the status field of the
trace resource.

See the corresponding [gadgets specs](./crds/) to
find out what's available.

Note that **all traces should be created in the `gadget` namespace**. And,
for now, the node name needs to be explicitly set in the trace.

### Setting the `Trace` operation

Once the `Trace` resource is created, the `gadget.kinvolk.io/operation`
field is used to control when the gadget should run.

Some gadgets accept a single operation that triggers a run and stores the
output. Other gadgets need to be started and stay running until they get
stopped later on to obtain the output.

To control whether a gadget should get started or stopped, annotate the
corresponding trace resource with
`gadget.kinvolk.io/operation=<operation-name>`

Note that the trace controller will remove the annotation after it has
processed it. So, if you find yourself having to forcefully overwrite the
value of this field, it means that the trace controller is having trouble
processing your `Trace` resource.

### Using `Trace` resources from the command line

It's possible to create and interact with the `Trace` resources directly
from the command line, using `kubectl apply` with a YAML file containing
the specified trace.

After creating the resource, the corresponding operation can be set with
`kubectl annotate`, as in the following example:

```bash
$ kubectl annotate -n gadget trace/trace-name gadget.kinvolk.io/operation=start
```

### Using `Trace` resources from graphical interfaces

Graphical interfaces that interact with Kubernetes, can integrate with
Inspektor Gadget by creating and modifying `Trace` resources in the
`gadget` namespace, and following the corresponding gadget specifications.

Gadgets can then be controlled by annotating the
`gadget.kinvolk.io/operation` field with the corresponding operation.

As an example, see the [biolatency
plugin](https://github.com/kinvolk/lokomotive-web-ui/blob/main/plugins/biolatency/src/index.tsx)
implementation for Headlamp.

### Interacting with traces using the `kubectl-gadget` CLI

The `kubectl-gadget` plugin may create, annotate and delete `Trace`
resources as necessary to interact with the `gadget` DaemonSet running on
the nodes. This is mostly transparent to the user, who will just get the
results through the command-line.
