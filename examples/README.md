# examples

This folder contains some examples showing the usage of the Golang
packages provided by Inspektor Gadget. These examples are designed for
developers that want to use the Golang packages exposed by Inspektor
Gadget directly. End-users do not need this and can use `kubectl-gadget`
or `ig` directly.

- [container-hook](container-hook/): Use of the container-hook package to
  - receive notifications when a container starts or terminates
  - execute PreStart and PostStop hooks
- [container-collection](container-collection/): Use the
  container-collection package
  ("github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection") to
  print a message when a container is created or removed.
- [kube-container-collection](kube-container-collection/): Use the
  container-collection package
  ("github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection") in
  order to be notified when a new container is started and to attach the
  OCI config.json as a Kubernetes event.
- (image-based) gadgets:
  - Check list of examples in [gadgets](gadgets)
