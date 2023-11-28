---
title: 'Running a containerized gadget'
weight: 20
description: >
  The run command allows to create an instance of a gadget.
---

> ⚠️ This command is experimental and could change without prior notification. Only few gadgets are supported and we're working to extend this support.
Check the installation guide to enable [experimental features](../install.md#experimental-features).

The `run` command runs a gadget from an OCI image. Check the different gadgets available in https://github.com/orgs/inspektor-gadget/packages.

## On Kubernetes

```bash
$ kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_tcpconnect:latest
INFO[0000] Experimental features enabled
K8S.NODE               K8S.NAMESPACE         K8S.POD               K8S.CONTAINER         PID     TASK        SRC                      DST
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:37848   r/1.1.1.1:80
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:33150   r/1.1.1.1:443

$ kubectl gadget run ghcr.io/inspektor-gadget/gadget/trace_open:latest
INFO[0000] Experimental features enabled
K8S.NODE               K8S.NAMESPACE          K8S.POD                K8S.CONTAINER          PID     COMM        UID      GID      RET FNAME
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

## With `ig`

``` bash
$ sudo ig run ghcr.io/inspektor-gadget/gadget/trace_tcpconnect:latest
INFO[0000] Experimental features enabled
RUNTIME.CONTAINERNAME                                            PID     TASK             SRC                                DST
mycontainer3                                                     1254254 wget             172.17.0.4:50072                   1.1.1.1:80
mycontainer3                                                     1254254 wget             172.17.0.4:44408                   1.1.1.1:443

$ sudo ig run ghcr.io/inspektor-gadget/gadget/trace_open:latest
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
