---
title: 'Running a containerized gadget'
weight: 20
description: >
  The run command allows to create an instance of a gadget.
---

> ⚠️ This command is experimental and could change without prior notification. Only few gadgets are supported and we're working to extend this support.
Check the installation guide to enable [experimental features](../install.md#experimental-features).

The `run` gadget launches a gadget. Currently only local gadgets are supported and must be specified by using the following flags:
- `--prog`: Compiled eBPF object.
- `--definition`: Yaml file indicating the output format of the gadget.

The [gadgets](../../gadgets) folder include some sample gadgets to be used with this command.

## On Kubernetes

```bash
$ kubectl gadget run --prog @./gadgets/trace_tcpconnect_x86.bpf.o --definition @./gadgets/trace_tcpconnect.yaml
INFO[0000] Experimental features enabled
K8S.NODE               K8S.NAMESPACE         K8S.POD               K8S.CONTAINER         PID     TASK        SRC                      DST
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:37848   r/1.1.1.1:80
ubuntu-hirsute         default               mypod2                mypod2                174085  wget        p/default/mypod2:33150   r/1.1.1.1:443

$ kubectl gadget run --prog @./gadgets/trace_open_x86.bpf.o --definition @./gadgets/trace_open.yaml
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

## With `ig`

``` bash
$ sudo ig run --prog @./gadgets/trace_tcpconnect_x86.bpf.o --definition @./gadgets/trace_tcpconnect.yaml
RUNTIME.CONTAINERNAME                                            PID     TASK             SRC                                DST
mycontainer3                                                     1254254 wget             172.17.0.4:50072                   1.1.1.1:80
mycontainer3                                                     1254254 wget             172.17.0.4:44408                   1.1.1.1:443

$ sudo ig run --prog @./gadgets/trace_open_x86.bpf.o --definition @./gadgets/trace_open.yaml
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
