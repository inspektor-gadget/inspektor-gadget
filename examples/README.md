# examples

This folder contains some examples showing the usage of the Golang
packages provided by Inspektor Gadget. These examples are designed for
developers that want to use the Golang packages exposed by Inspektor
Gadget directly. End-users do not need this and can use `kubectl-gadget`
or `local-gadget` directly.

- [runc-hook](runc-hook/): Use of the runcfanotify package to
  - receive notifications when a container starts or terminates
  - execute PreStart and PostStop hooks
- [kube-container-collection](kube-container-collection/): Use the
  container-collection package
  ("github.com/kinvolk/inspektor-gadget/pkg/container-collection") in
  order to be notified when a new container is started and to attach the
  OCI config.json as a Kubernetes event.
- gadgets:
  - [trace/exec](gadgets/trace/exec/): shows how to use
    [trace/exec](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/trace/exec)
    package to trace the creation of new processes in the host.
  - [top/file](gadgets/top/file/): shows how to use
    [top/file](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/top/file)
    package to get a list of the files with a higher number of write
    operations on the host.
  - [snapshot/process](gadgets/snapshot/process/): shows how to use
    [snapshot/process](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/snapshot/process)
    package to get a list the running processes on the host.
