---
title: Installing on Kubernetes
sidebar_position: 100
description: Getting Started on Kubernetes
---

Inspektor Gadget is composed of a `kubectl` plugin executed in the user's
system and a DaemonSet deployed in the cluster.

## Installing kubectl gadget

Choose one way to install the Inspektor Gadget `kubectl` plugin.

### Using krew

[krew](https://sigs.k8s.io/krew) is the recommended way to install
`kubectl gadget`. You can follow the
[krew's quickstart](https://krew.sigs.k8s.io/docs/user-guide/quickstart/)
to install it and then install `kubectl gadget` by executing the following
commands.

```bash
$ kubectl krew install gadget
$ kubectl gadget --help
```

### Install a specific release

Download the asset for a given release and platform from the
[releases page](https://github.com/inspektor-gadget/inspektor-gadget/releases/),
uncompress and move the `kubectl-gadget` executable to your `PATH`.

```bash
$ IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)
$ IG_ARCH=amd64
$ curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/kubectl-gadget-linux-${IG_ARCH}-${IG_VERSION}.tar.gz  | sudo tar -C /usr/local/bin -xzf - kubectl-gadget
$ kubectl gadget version
```

### Compile from source

To build Inspektor Gadget from source, you'll need to have a Golang version
1.22 or higher installed.

```bash
$ git clone https://github.com/inspektor-gadget/inspektor-gadget.git
$ cd inspektor-gadget
$ make kubectl-gadget-linux-amd64
$ sudo cp kubectl-gadget-linux-amd64 /usr/local/bin/kubectl-gadget
$ kubectl gadget version
```

## Installing in the cluster

### Quick installation

```bash
$ kubectl gadget deploy
```

This will deploy the gadget DaemonSet along with its RBAC rules.

![Screencast of the deploy command](../install.gif)

### Choosing the gadget image

If you wish to install an alternative gadget image, you could use the following commands:

```bash
$ kubectl gadget deploy --image=ghcr.io/myfork/inspektor-gadget:tag
```

### Deploy to specific nodes

The `--node-selector` flag accepts a [label
selector](https://kubernetes.io/docs/concepts/overview/working-with-objects/labels/#label-selectors)
that defines the nodes where Inspektor Gadget will be deloyed to:

```bash
# Deploy only to the minikube-m02 node
$ kubectl gadget deploy --node-selector kubernetes.io/hostname=minikube-m02

# Deploy to all nodes but minikube
$ kubectl gadget deploy --node-selector kubernetes.io/hostname!=minikube

# Deploy to minikube and minikube-m03 nodes only
$ kubectl gadget deploy --node-selector 'kubernetes.io/hostname in (minikube, minikube-m03)'
```

### Deploying into a custom namespace

By default Inspektor Gadget is deployed to the namespace `gadget`.
This can be changed with the `--gadget-namespace` flag.
When using gadgets (e.g. `kubectl gadget trace exec`) the deployed namespace is discovered automatically and no additional flags are needed during the usage.
For `undeploy` the `--gadget-namespace` flag is mandatory.

### Hook Mode

Inspektor Gadget needs to detect when containers are started and stopped.
The different supported modes can be set by using the `hook-mode` option:

- `auto`(default): Inspektor Gadget will try to find the best option based on
  the system it is running on.
- `crio`: Use the [CRIO
  hooks](https://github.com/containers/podman/blob/v3.4.4/pkg/hooks/docs/oci-hooks.5.md)
  support. Inspektor Gadget installs the required hooks in
  `/etc/containers/oci/hooks.d`, be sure that path is part of the `hooks_dir`
  option on
  [crio.conf](https://github.com/cri-o/cri-o/blob/v1.20.0/docs/crio.conf.5.md#crioruntime-table).
  If `hooks_dir` is not declared at all, that path is considered by default.
- `podinformer`: Use a Kubernetes controller to get information about new pods.
  This option is racy and the first events produced by a container could be
  lost. This mode is selected when `auto` is used and the above modes are not
  available.
- `nri`: Use the [Node Resource Interface](https://github.com/containerd/nri).
  It requires containerd v1.5 and it's not considered when `auto` is used.
- `fanotify`: Uses the Linux
  [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API. It
  works with both runc and crun. It requires to run in the host pid namespace
  (`hostPID=true`).
- `fanotify+ebpf`:  Uses the Linux
  [fanotify](https://man7.org/linux/man-pages/man7/fanotify.7.html) API and an
  eBPF module. It works with both runc and crun. It works regardless of the
  pid namespace configuration.

### Deploying with an AppArmor profile

By default, Inspektor Gadget runs as unconfined because it needs to write to different files under `/sys`.
It is nonetheless possible to deploy Inspektor Gadget using a custom AppArmor profile with the `--apparmor-profile` flag:

```bash
$ kubectl gadget deploy --apparmor-profile 'localhost/inspektor-gadget-profile'
```

Note that, the AppArmor profile should already exists in the cluster to be used.

### Deploying with a seccomp profile

By default, Inspektor Gadget syscalls are not restricted.
If the seccomp profile operator is [installed](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md#install-operator), you can use the `--seccomp-profile` flag to deploy Inspektor Gadget with a custom seccomp profile.
Note that, the profile should follow the [`SeccompProfile` format](https://github.com/kubernetes-sigs/security-profiles-operator/blob/main/installation-usage.md#create-a-seccomp-profile):

```bash
$ cat 'gadget-profile.yaml'
apiVersion: security-profiles-operator.x-k8s.io/v1beta1
kind: SeccompProfile
metadata:
  namespace: gadget
  name: profile
spec:
  defaultAction: SCMP_ACT_ERRNO
  syscalls:
    - action: SCMP_ACT_ALLOW
      names:
        - accept4
        - access
        - arch_prctl
        - bind
...
$ kubectl gadget deploy --seccomp-profile 'gadget-profile.yaml'
```

### Helm Chart Installation

Inspektor Gadget can also be installed using our [official Helm chart](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/charts). To install using Helm, run the following commands:

```bash
$ helm repo add gadget https://inspektor-gadget.github.io/charts
$ helm install gadget gadget/gadget --namespace=gadget --create-namespace
```

For more information on the Helm chart, please refer to the [Helm Chart documentation](https://artifacthub.io/packages/helm/gadget/gadget).

Also, all the above configurations options can be passed as [values](https://artifacthub.io/packages/helm/gadget/gadget#values) to the Helm chart.

### Verifying the Inspektor Gadget Image

When deploying Inspektor Gadget using `kubectl gadget deploy`, the image will be automatically verified if the `policy-controller` is deployed on your Kubernetes cluster.
To do so, you first need to [install](https://docs.sigstore.dev/policy-controller/installation/) this component.
Now, let's deploy Inspektor Gadget in a cluster where the `policy-controller` is present:

```bash
$ kubectl get pod -n cosign-system
NAME                                         READY   STATUS    RESTARTS   AGE
policy-controller-webhook-7c7f55dfcf-qkpw4   1/1     Running   0          10s
$ kubectl gadget deploy
...
1/1 gadget pod(s) ready
...
Inspektor Gadget successfully deployed
```

As you can see, everything was successfully deployed.
Now, let's undeploy Inspektor Gadget and try to deploy an old release which was not signed:

```bash
$ kubectl gadget undeploy
...
Inspektor Gadget successfully removed
$ kubectl gadget deploy --image 'ghcr.io/inspektor-gadget/inspektor-gadget:v0.22.0'
...
Creating DaemonSet/gadget...
Error: problem while creating resource: creating "DaemonSet": admission webhook "policy.sigstore.dev" denied the request: validation failed: failed policy: gadget-image-policy: spec.template.spec.containers[0].image
ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f signature key validation failed for authority authority-0 for ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f: no matching signatures
```

As this image is not signed, the verification failed and the container was not deployed to the cluster.

In case the `policy-controller` is not present, a warning message will be printed to inform you the verification will not take place:

```bash
$ kubectl get pod -n cosign-system
No resources found in cosign-system namespace.
$ kubectl gadget deploy
WARN[0000] No policy controller found, the container image will not be verified
...
Inspektor Gadget successfully deployed
```

#### Skipping verification

You can also decide to not verify the image, using `--verify-image=false`.
However, we definitely recommend enabling this security feature.

```bash
$ kubectl gadget deploy --verify-image=false
WARN[0000] You used --verify-image=false, the container image will not be verified
...
Inspektor Gadget successfully deployed
```

#### Using custom public key for verification

To verify the image with a specific key, you can use the `--public-key` flag:

```bash
$ kubectl gadget deploy --public-key="$(cat pkg/resources/inspektor-gadget.pub)"
```

### Other Deploy Options

Please check the following documents to learn more about different options:
- [Restricting the Gadgets that can be run](./restricting-gadgets.mdx)
- [Using Insecure Registries](./insecure-registries.mdx)
- [Verifying Gadget Images](./verify-assets.md#verify-image-based-gadgets)

### Experimental features

Inspektor Gadget has some experimental features disabled by default. Users can enable those
features, however they don't provide any stability and could be removed at any time.

`kubectl gadget deploy` provides an `--experimental` flag to enabled them.

```bash
$ kubectl gadget deploy --experimental
$ kubectl logs -n gadget $PODNAME -f | grep -i experimental
...
time="2023-06-15T15:20:03Z" level=info msg="Experimental features enabled"
...

$ kubectl gadget run trace_exec
INFO[0000] Experimental features enabled
...
```
### Specific Information for Different Platforms

This section explains the additional steps that are required to run Inspektor
Gadget in some platforms.

#### Minikube

You can deploy Inspektor Gadget in `minikube` in different ways:
- Manually, using the `kubectl gadget deploy` command as described above.
- Using the [Inspektor Gadget Addon](https://minikube.sigs.k8s.io/docs/handbook/addons/inspektor-gadget/) available
  since [minikube v1.31.0](https://github.com/kubernetes/minikube/releases).

We recommend to use the `docker` driver:

```bash
$ minikube start --driver=docker
# Deploy Inspektor Gadget in the cluster as described above
```

But can also use the `kvm2` one:

```bash
$ minikube start --driver=kvm2
# Deploy Inspektor Gadget in the cluster as described above
```

### Private registries

In order to use private registries, you will need a [Kubernetes secret](https://kubernetes.io/docs/tasks/configure-pod-container/pull-image-private-registry/) having credentials to access the registry.

There are two different ways to use this support:

#### Defining a default secret when deploying Inspektor Gadget

This approach creates a secret that will be used by default when pulling the gadget images. It requires to have a `docker-registry` secret named `gadget-pull-secret` in the `gadget` namespace:

Let's create the `gadget` namespace if it doesn't exist:

```bash
$ kubectl create namespace gadget
```

then create the secret:

```bash
$ kubectl create secret docker-registry gadget-pull-secret -n gadget --docker-server=MYSERVER --docker-username=MYUSERNAME --docker-password=MYPASSWORD
```

or you can create the secret from a file:

```bash
$ kubectl create secret docker-registry gadget-pull-secret -n gadget --from-file=.dockerconfigjson=$HOME/.docker/config.json
```

then, deploy Inspektor Gadget:

```bash
$ kubectl gadget deploy ...
```

this secret will be used by default when running a gadget:


```bash
$ kubectl gadget run myprivateregistry.io/trace_tcpconnect:latest
```

#### Specifying the secret when running a gadget

It's possible to pass a secret each time a gadget is run, you'd need to follow a similar approach as above to create the secret:

```bash
# from credentials
$ kubectl create secret docker-registry my-pull-secret -n gadget --docker-server=MYSERVER --docker-username=MYUSERNAME --docker-password=MYPASSWORD

# from a file
$ kubectl create secret docker-registry my-pull-secret -n gadget --from-file=.dockerconfigjson=$HOME/.docker/config.json
```

Then, it can be used each time a gadget is run:

```bash
$ kubectl gadget run myprivateregistry.io/trace_tcpconnect:latest --pull-secret my-pull-secret
```

You can specify the pull secret as part of configuration file to avoid specifying it each time you run a gadget:

```yaml
# ~/.ig/config.yaml
operator:
  oci:
    pull-secret: "my-pull-secret"
```

For more information about the configuration file, check the [configuration guide](./configuration.md).

## Uninstalling from the cluster

The following command will remove all the resources created by Inspektor
Gadget from the cluster:

```bash
$ kubectl gadget undeploy
```

## Version skew policy

Inspektor Gadget requires the kubectl-gadget plugin and the DaemonSet
deployed on the cluster to be the exact same version. Even if this is
possible that different versions work well together, we don't provide
any guarantee in those cases. We'll visit this policy again once we
approach to the v1.0 release.
