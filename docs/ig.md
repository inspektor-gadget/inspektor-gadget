---
title: ig
weight: 80
description: >
  Description of the ig tool.
---

Inspektor Gadget relies on the Kubernetes API server to work. However, there are
[some cases](#use-cases) where it is necessary, or preferred, to trace
containers without passing through Kubernetes. In such scenarios, you can use
the `ig` tool, as it allows you to collect insights from the nodes to
debug your Kubernetes containers without relying on Kubernetes itself, but on
the container runtimes. It is important to remark that `ig` can also
be used to trace containers that were not created via Kubernetes.

Some characteristics of `ig`:

- It uses eBPF as its underlying core technology.
- Enriches the collected data with the Kubernetes metadata.
- Easy to install as it is a single binary (statically linked).

The architecture of `ig` is described in the main
[architecture](architecture.md#ig) document.

## Use cases

- In a Kubernetes environment, when the Kubernetes API server is not working
  properly, we cannot deploy Inspektor Gadget. Therefore, we still need a way to
  debug the containers of the cluster.
- In some cases, you might have root SSH access to the Kubernetes nodes of a
  cluster, but not to the `kubeconfig`.
- If you don't want to install `kubectl-gadget` on your machine, you can run
  `ig` in a Kubernetes pod and read the output directly.
- If you are implementing an application that needs to get insights from the
  Kubernetes node, you could include the `ig` binary in your container
  image, and your app simply execs it. In such a case, it is suggested to use
  the JSON output format to ease the parsing.
- Outside a Kubernetes environment, for observing and debugging standalone
  containers.

## Installation

The instruction to install `ig` are available in the main
[installation](install.md#installing-ig) guide.

## Usage

Currently, `ig` can trace containers managed by Docker regardless
of whether they were created via Kubernetes or not. In case of containerd,
we are using containerd API directly but only `k8s.io` namespace is supported,
meaning only the ones created via Kubernetes. In addition, it can also use the CRI to
trace containers managed by CRI-O, Support for non-Kubernetes containers with
containerd is coming, see issue
[#1849](https://github.com/inspektor-gadget/inspektor-gadget/issues/1849).

**Note:** We only support CRI v1 meaning that only CRI-O v1.20+ (compatible with Kubernetes v1.20+) is supported.

By default, `ig` will try to communicate with all the supported container runtimes (docker, containerd, CRI-O, podman):

```bash
$ docker run -d --name myContainer nginx:1.21
95b814bb82b9e30dd935b03d04a7b00b6978ce018a6f55d6a9c7a824b31ec6b5

$ sudo ig list-containers
RUNTIME.RUNTIMENAME RUNTIME.CONTAINERID                                              RUNTIME.CONTAINERNAME
containerd          c7dfa4c92fec235626157417bf45745969006bd3bfd2607e87fdd0a176547603 konnectivity-agent
containerd          cd8ce885c115adbc87da5243630b90935e5bf1c2af96b00154ec475fd9b393b0 nsenter
containerd          b436a9886ee6e59ac7d38d1b76f8a306e2efeb3f1b6679ea1a58028edb198db3 azure-ip-masq-agent
containerd          642fc58b15fbaf578340f4bd656b427db51be63a94a7b6eb663388486e73d855 azuredisk
containerd          466a9d7e7b2087966621eacd792cc492f48f08f741f9dc82d88ef62a9d7d3e0f liveness-probe
containerd          f79db0f2ea6518869c89e1d0a0892221047b23e04e4dab59dc7e42d6808e2530 azurefile
containerd          85d74aeb6d29aaa38b282f3e51202bb648f7ba16a681d0d39dda684e724bb8a3 node-driver-registrar
containerd          a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46 kube-proxy
containerd          428c933882f1e4459c397da20bd89bbe7df7d437880a254472879d33b125b4da node-driver-registrar
containerd          cd75a08ea2e69756cd7b1de5935c49f5ba08ba7495b0589567dcd9493193d712 cloud-node-manager
containerd          d4bdf83ba71c7b22ee339ae5bb6fa7359f8a6bc7cd2f35ccd5681c728869cd39 liveness-probe
docker              b72558e589cb95e835c4840de19f0306d4081091c34045246d62b6efed3549f4 myContainer
```

To check which paths `ig` is using, you can use the `--help` flag:

```bash
$ sudo ig list-containers --help
List all containers

Usage:
  ig list-containers [flags]

Flags:
  ...
      --containerd-socketpath string   containerd CRI Unix socket path (default "/run/containerd/containerd.sock")
      --crio-socketpath string         CRI-O CRI Unix socket path (default "/run/crio/crio.sock")
      --docker-socketpath string       Docker Engine API Unix socket path (default "/run/docker.sock")
      --podman-socketpath string       Podman Unix socket path (default "/run/podman/podman.sock")
  ...
  -r, --runtimes string                Container runtimes to be used separated by comma. Supported values are: docker, containerd, cri-o, podman (default "docker,containerd,cri-o,podman")
  -w, --watch                          After listing the containers, watch for new containers
  ...
```

If needed, we can also specify the runtimes to be used and their UNIX socket
path:

```bash
$ sudo ig list-containers --runtimes docker --docker-socketpath /some/path/docker.sock
RUNTIME.RUNTIMENAME RUNTIME.CONTAINERID                                              RUNTIME.CONTAINERNAME
docker              b72558e589cb95e835c4840de19f0306d4081091c34045246d62b6efed3549f4 myContainer
```

### Common features

Notice that most of the commands support the following features even if, for
simplicity, they are not demonstrated in each command guide:

- JSON format and `custom-columns` output mode are supported through the
  `--output` flag.
- It is possible to filter events by container name using the `--containername`
  flag.
- It is possible to trace events from all the running processes, even though
  they were not generated from containers, using the `--host` flag.

For instance, for the `list-containers` command:

```bash
$ sudo ig list-containers -o json --containername kube-proxy
[
  {
    "runtime": {
      "runtimeName": "containerd",
      "containerId": "a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46",
      "containerName": "kube-proxy"
    },
    "k8s": {
      "namespace": "kube-system",
      "podName": "kube-proxy-tcbn4",
      "containerName": "kube-proxy",
      "podUID": "87c52d60-fefd-45a9-a420-895256fc03b5"
    },
    "pid": 454674,
    "mntns": 4026532232,
    "netns": 4026531840,
    "hostNetwork": true,
    "cgroupPath": "/sys/fs/cgroup/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod87c52d60_fefd_45a9_a420_895256fc03b5.slice/cri-containerd-a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46.scope",
    "cgroupID": 41286,
    "cgroupV2": "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod87c52d60_fefd_45a9_a420_895256fc03b5.slice/cri-containerd-a126df15fba5713f57f1abad9c484cb75569e9f48f1169bd9710f63bb8af0e46.scope"
  }
]
```

For example, with `--host`, you can get the following output:

```bash
$ sudo ig trace exec --host
RUNTIME.CONTAINERNAME    PID        PPID       COMM             RET ARGS

# Open another terminal.
$ cat /dev/null
$ docker run --name test-host --rm -t debian sh -c 'ls > /dev/null'
# Go back to first terminal.
RUNTIME.CONTAINERNAME    PID        PPID       COMM             RET ARGS
                         3326022    308789     cat              0   /usr/bin/cat /dev/null
test-host                3326093    3326070    sh               0   /usr/bin/sh -c ls > /dev/null
test-host                3326123    3326093    ls               0   /usr/bin/ls
```

Events generated from containers have their container field set, while events which are generated from the host do not.

### Using ig with "kubectl debug node"

The "kubectl debug node" command is documented in
[Debugging Kubernetes Nodes With Kubectl](https://kubernetes.io/docs/tasks/debug/debug-cluster/kubectl-node-debug/).

Examples of commands:

```bash
$ kubectl debug node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig -- ig --auto-sd-unit-restart trace exec
Creating debugging pod node-debugger-minikube-docker-c2wfw with container debugger on node minikube-docker.
If you don't see a command prompt, try pressing enter.
RUNTIME.CONTAINERNAME          PID              PPID             COMM             RET ARGS
k8s_shell_shell_default_b4ebb… 3186934          3186270          cat              0   /bin/cat file
```

```bash
$ kubectl debug node/minikube-docker -ti --image=ghcr.io/inspektor-gadget/ig -- ig --auto-sd-unit-restart list-containers -o json
```

As of today, the `kubectl debug` command does not have a way to give enough privileges to the debugging pod to be able
to use `ig`.
This might change in the future: the Kubernetes Enhancement Proposal 1441
([KEP-1441](https://github.com/kubernetes/enhancements/tree/master/keps/sig-cli/1441-kubectl-debug))
suggests to implement Debugging Profiles (`--profile=`) to be able to give the necessary privileges.
kubectl v1.27 implements some of those profiles but not yet the "sysadmin" profile, so it is not possible to use
`--profile=` yet.

Meanwhile, `ig` provides the `--auto-sd-unit-restart` flag. The flag is `false` by default. When it is set to `true`,
`ig` will detect if it does not have enough privileges and it can transparently
re-execute itself in a privileged systemd unit if necessary.
This is possible because the "kubectl debug node" gives access to the systemd socket (`/run/systemd/private`) via the
/host volume.

### Using ig in a container

Example of command:

```bash
$ docker run -ti --rm \
    --privileged \
    -v /run:/run \
    -v /:/host \
    -v /sys/kernel/debug:/sys/kernel/debug \
    -v /sys/kernel/tracing:/sys/kernel/tracing \
    -v /sys/fs/bpf:/sys/fs/bpf \
    --pid=host \
    ghcr.io/inspektor-gadget/ig \
    trace exec
RUNTIME.CONTAINERNAME    PID        PPID       COMM             RET ARGS
heuristic_yonath         3329233    3329211    ls               0   /bin/ls
```

List of flags:
- `--privileged` gives all capabilities such as `CAP_SYS_ADMIN`. It is required to run eBPF programs.
- `-v /run:/run` gives access to the container runtimes sockets (docker, containerd, CRI-O).
- `-v /:/host` gives access to the host filesystem. This is used to access the host processes via /host/proc, and access
  container runtime hooks (rootfs and config.json).
- `-v` volumes for debugfs, tracefs and bpf filesystems. Alternatively, it is possible to pass the flag
  `--auto-mount-filesystems` to ig to automatically mount those filesystems.
- `--pid=host` runs in the host PID namespace. Optional on Linux. This is necessary on Docker Desktop on Windows because
  /host/proc does not give access to the host processes.

### Using ig in a Kubernetes pod

In order to run `ig` in a Kubernetes pod use [examples/pod-ig.yaml](examples/pod-ig.yaml).

```bash
$ kubectl apply -f docs/examples/pod-ig.yaml
$ kubectl logs ig
RUNTIME.CONTAINERNAME          RUNTIME.CONTAIN… PID              PPID             COMM             RET ARGS
kube-proxy                     k8s.gcr.io/kube… 3985376          3024961          ip6tables        0   /usr/sbin/ip6tables -w 5 -W 100000 -S K…
```

### Adding ig in your own container image

In order to add `ig` in your own container image, you can take example on the following Dockerfile:

```Dockerfile
# In production, you should use a specific version of ig instead of latest:
# --build-arg BASE_IMAGE=ghcr.io/inspektor-gadget/ig:v0.18.1
ARG BASE_IMAGE=ghcr.io/inspektor-gadget/ig:latest
FROM ${BASE_IMAGE} as ig

# Your own image
FROM alpine:3.17
COPY --from=ig /usr/bin/ig /usr/bin/ig
ENV HOST_ROOT=/host
# The rest of your Dockerfile
```

The `ghcr.io/inspektor-gadget/ig` image supports amd64 and arm64. Your own image can also support both architectures if
you use the appropriate `--platforms` flag of `docker buildx build` (see
[Docker documentation about multi-platform images](https://docs.docker.com/build/building/multi-platform/#example)).

You can then run your image locally or in a Kubernetes pod.
Here is an example using a Kubernetes DaemonSet: [examples/ds-ig.yaml](examples/ds-ig.yaml):

```bash
$ kubectl apply -f docs/examples/ds-ig.yaml
$ kubectl exec -ti $(kubectl get pod -o name -l name=example-ig | head -1) -- sh
/ # ig trace exec
```