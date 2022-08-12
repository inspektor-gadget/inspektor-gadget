# examples

This folder contains some examples showing the usage of the Golang
packages provided by Inspektor Gadget. These examples are designed for
developers that want to use the Golang packages exposed by Inspektor
Gadget directly. End-users do not need this and can use `kubectl-gadget`
or `local-gadget` directly.

- [runc-hook](runc-hook/): Use of the runcfanotify package to
  - receive notifications when a container starts or terminates
  - execute PreStart and PostStop hooks
- [container-collection](container-collection/): Use the
  container-collection package
  ("github.com/kinvolk/inspektor-gadget/pkg/container-collection") to
  print a message when a container is created or removed.
- [kube-container-collection](kube-container-collection/): Use the
  container-collection package
  ("github.com/kinvolk/inspektor-gadget/pkg/container-collection") in
  order to be notified when a new container is started and to attach the
  OCI config.json as a Kubernetes event.
- gadgets:
  - [basic](gadgets/basic/): Examples showing how to create a tracer
    without any filtering capabilities.
    - [trace/exec](gadgets/basic/trace/exec/): shows how to use
      [trace/exec](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/trace/exec)
      package to trace the creation of new processes in the host.
    - [top/file](gadgets/basic/top/file/): shows how to use
      [top/file](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/top/file)
      package to get a list of the files with a higher number of write
      operations on the host.
    - [snapshot/basic/process](gadgets/snapshot/process/): shows how to use
      [snapshot/process](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/snapshot/process)
      package to get a list the running processes on the host.
  - [withfilter](gadgets/withfilter/): Examples showing how to create a
    tracer that uses the container collection and trace collection
    packages to filter events by container.
    - [trace/exec](gadgets/withfilter/trace/exec/): traces creation of
      new processes inside a particular container.
  - [parser](gadgets/parser/): Examples showing how to use a parser to
    format the events.
    - [trace/exec](gadgets/parser/trace/exec/): traces creation of
      new processes inside a particular container.
