---
title: 'Running a gadget'
weight: 20
description: >
  The run command allows to create an instance of a gadget.
---

> [!WARNING]
> This command is experimental and could change without prior notification. Only few gadgets are supported and we're working to extend this support.
Check the installation guide to enable [experimental features](../getting-started/install-linux.md#experimental-features).

The `run` command runs a gadget from an OCI image. By default, the `run` command will use following defaults to refer the OCI image:
- `ghcr.io` as the registry
- `inspektor-gadget/gadget` as the repository prefix
- `latest` as the tag

Check the different gadgets available in https://github.com/orgs/inspektor-gadget/packages.

## On Kubernetes

```bash
$ kubectl gadget run trace_tcpconnect
INFO[0000] Experimental features enabled
K8S.NODE               K8S.NAMESPACE         K8S.PODNAME           K8S.CONTAINERNAME     PID     TASK        SRC                      DST
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:37848   r/1.1.1.1:80
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:33150   r/1.1.1.1:443

$ kubectl gadget run trace_open
INFO[0000] Experimental features enabled
K8S.NODE               K8S.NAMESPACE          K8S.PODNAME            K8S.CONTAINERNAME      PID     COMM        UID      GID      RET FNAME
ubuntu-hirsute         default                mypod2                 mypod2                 225071  sh          0        0        3   /
ubuntu-hirsute         default                mypod2                 mypod2                 225071  sh          0        0        3   /root/.ash_history
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /etc/ld.so.cache
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/gl
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/tl
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/tl
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/tl
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/tl
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/x8
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/x8
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/x8
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64-linux-gnu/li
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /usr/lib/x86_64-linux-gn
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/glibc-hwcaps/x86-64
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/tls/x86_64/x86_64/l
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/tls/x86_64/libm.so.
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/tls/x86_64/libm.so.
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/tls/libm.so.6
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64/x86_64/libm.
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64/libm.so.6
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        -2  /lib/x86_64/libm.so.6
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        3   /lib/libm.so.6
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        3   /lib/libresolv.so.2
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        3   /lib/libc.so.6
ubuntu-hirsute         default                mypod2                 mypod2                 242164  cat         0        0        3   /dev/null
```

### Private registries in Kubernetes

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

For more information about the configuration file, check the [configuration guide](#configuration-file).

### Restricting gadget images (by registry or digest)

This is possible to restrict the executed gadgets by using the `--allowed-gadgets` flag.
By default, all gadgets are allowed.
You can specify these options only at deploy time:

```bash
$ kubectl gadget deploy --gadgets-public-keys="$(cat inspektor-gadget.pub),$(cat your-key.pub)" --allowed-gadgets='ghcr.io/inspektor-gadget/gadget@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f,ghcr.io/your-repo/gadget@sha256:digest_of_your_gadget'
...
Inspektor Gadget successfully deployed
$ kubectl gadget run trace_exec
K8S.NAMESPACE    K8S.PODNAME      K8S.CONTAINERNA… COMM            PID      TID PCOMM        PPID ARGS     K8S.NODE E… TIMESTAMP
gadget           gadget-fdpxp     gadget           gadgettr…    131299   131299 runc       131281 /bin/ga… minikub…    2024-07-25T08:22:…
gadget           gadget-fdpxp     gadget           gadgettr…    131298   131298 runc       131280 /bin/ga… minikub…    2024-07-25T08:22:…
^C
$ kubectl gadget run trace_open
Error: fetching gadget information: getting gadget info: rpc error: code = Unknown desc = getting gadget info: initializing and preparing operators: instantiating operator "oci": ensuring image: trace_open is not part of allowed gadgets: ghcr.io/inspektor-gadget/gadget@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f, ghcr.io/your-repo/gadget@sha256:digest_of_your_gadget
$ kubectl gadget run ghcr./io/your-repo/gadget/your_gadget
K8S.NAMESPACE  K8S.PODNAME    K8S.CONTAINER… TIMEST… PID     UID     GID     MNTNS_… ERR     FD      FLAGS   MODE    COMM   FNAME  K8S.N…
gadget         gadget-8rcdz   gadget         500159… 134426  0       0       402653… 0       5       0       0       runc:… /sys/… minik…
gadget         gadget-8rcdz   gadget         500159… 134427  0       0       402653… 0       5       0       0       runc:… /sys/… minik…
^C
```

## With `ig`

``` bash
$ sudo ig run trace_tcpconnect
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                                            PID     TASK             SRC                                DST
mycontainer3                                                     1254254 wget             172.17.0.4:50072                   1.1.1.1:80
mycontainer3                                                     1254254 wget             172.17.0.4:44408                   1.1.1.1:443

$ sudo ig run trace_open
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                               PID     COMM             UID      GID      RET       FNAME
mycontainer3                                        62162   sh               0        0        3         /
mycontainer3                                        62162   sh               0        0        3         /root/.ash_history
mycontainer3                                        122110  cat              0        0        -2        /etc/ld.so.cache
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/tls/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/tls/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64-linux-gnu/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/tls/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/tls/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /usr/lib/x86_64-linux-gnu/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/tls/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/tls/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/tls/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        -2        /lib/x86_64/libm.so.6
mycontainer3                                        122110  cat              0        0        3         /lib/libm.so.6
mycontainer3                                        122110  cat              0        0        3         /lib/libresolv.so.2
mycontainer3                                        122110  cat              0        0        3         /lib/libc.so.6
mycontainer3                                        122110  cat              0        0        3         /dev/null
```

### Restricting gadget images (by registry or digest)

We also offer this possibility with `ig` by using the same flags at run time:

```bash
$ sudo -E ig run --allowed-gadgets='ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f,ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d' trace_exec
RUNTIME.CONTAINERNAME    COMM                    PID           TID PCOMM                PPID ARGS         ER… TIMESTAMP
minikube-docker          iptables             137722        137722 kubelet             11713 /usr/sbin/i…     2024-07-25T10:30:21.902064…
minikube-docker          ip6tables            137723        137723 kubelet             11713 /usr/sbin/i…     2024-07-25T10:30:21.904561…
^C
$ sudo -E ig run ---allowed-gadgets='ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f,ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d' trace_open
RUNTIME.CONTAINER… COMM              PID       TID       UID       GID  FD FNAME                    MODE      ERROR  TIMESTAMP
minikube-docker    kubelet         11713     11715         0         0  20 /sys/fs/cgroup/kubepods… --------…        2024-07-25T10:30:44…
minikube-docker    kubelet         11713     11715         0         0  20 /proc/2136/fd            --------…        2024-07-25T10:30:44…
^C
$ sudo -E ig run --allowed-gadgetss='ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f,ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d' trace_signal
Error: fetching gadget information: initializing and preparing operators: instantiating operator "oci": ensuring image: trace_signal is not part of allowed gadgets: ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f, ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d
$ sudo -E ig run --allowed-gadgetss='ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f,ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d' ghcr.io/your-repo/gadget/your-gadget
Error: fetching gadget information: initializing and preparing operators: instantiating operator "oci": ensuring image: ghcr.io/your-repo/gadget/your-gadget is not part of allowed gadgets: ghcr.io/inspektor-gadget/gadget/trace_exec@sha256:e13e3859be5ed8cef676a720274480d2748f66fd98cf8d963af6c4c05121526f, ghcr.io/inspektor-gadget/gadget/trace_open@sha256:be8dd66efc69a14f2812b7d5472b378b095a2002ef89fa7aa1e33b7133da762d
```

## Environment Variables

You can use environment variables to configure the behavior of the `run` command. The environment variables use fully qualified names (as in the [configuration file]())
with the prefix `INSPEKTOR_GADGET_`.

```bash
# Enable verbose output
$ export INSPEKTOR_GADGET_VERBOSE=true
$ kubectl gadget run trace_open
INFO[0000] Experimental features enabled
DEBU[0000] using target "gadget-b7jrc" ("minikube-docker")
...
# Disable image verification (not recommended)
$ export INSPEKTOR_GADGET_OPERATOR_OCI_VERIFY_IMAGE=false
$ sudo ig run trace_open
INFO[0000] Experimental features enabled
WARN[0000] Ignoring runtime "cri-o" with non-existent socketPath "/run/crio/crio.sock"
WARN[0000] image signature verification is disabled due to using corresponding option
WARN[0000] image signature verification is disabled due to using corresponding option
...
```

## Configuration File

You can use a configuration file to set specific settings that persist across multiple executions. The default location for the configuration file is `~/.ig/config.yaml`.
You can change the location of the configuration file specifying the `--config` flag.

The default configuration file can be generated using the following command:

```bash
# Default configuration file for kubectl gadget
$ kubectl gadget config default
as: ""
as-group: []
as-uid: ""
cache-dir: /home/qasim/.kube/cache
...

# Default configuration file for ig
$ ig config default
INFO[0000] Experimental features enabled
auto-mount-filesystems: "false"
auto-wsl-workaround: "false"
operator:
    localmanager:
        containerd-namespace: k8s.io
...
# Default configuration file for gadgetctl
$ gadgetctl config default
operator:
    oci:
        allowed-digests: ""
        authfile: /var/lib/ig/config.json
        insecure: "false"
...
```

You can use the default configuration as a starting point (e.g. `ig config default > ~/.ig/config.yaml`) and modify it to suit your needs.

The current configuration can be printed using the following command:

```bash
# Print the current configuration for kubectl gadget
$ kubectl gadget config view
INFO[0000] Experimental features enabled
as: ""
as-group: []
as-uid: ""
cache-dir: /home/qasim/.kube/cache
...

# Print the current configuration for ig
$ ig config view
INFO[0000] Experimental features enabled
operator:
    localmanager:
        containerd-namespace: k8s.io
        runtimes: docker,containerd,cri-o,podman
...
# Print the current configuration for gadgetctl
$ gadgetctl config view
INFO[0000] Experimental features enabled
operator:
    oci:
        authfile: /var/lib/ig/config.json
        insecure: "false"
...
```

## Precedence

The precedence ([coming from viper](https://github.com/spf13/viper?tab=readme-ov-file#why-viper)) of the configuration settings is as follows:
- Flags passed to the command
- Environment variables
- Configuration file
- Default values