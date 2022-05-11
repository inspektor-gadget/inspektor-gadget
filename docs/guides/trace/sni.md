---
title: 'Using trace sni'
weight: 20
description: >
  Trace Server Name Indication (SNI) from TLS requests.
---

The trace sni gadget is used to trace the [Server Name Indication (SNI)](https://en.wikipedia.org/wiki/Server_Name_Indication) requests sent as part of TLS handshakes.

## How to use it?

The SNI tracer will show which pods are making which SNI requests. To start it,
we can run:

```bash
$ kubectl gadget trace sni
POD                            NAME
```

To generate some output for this example, let's create a demo pod in *another terminal*:

```bash
$ kubectl run -it ubuntu --image ubuntu:latest -- /bin/bash
root@ubuntu:/# apt update && apt install -y wget && wget wikimedia.org
(...)
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://www.wikimedia.org/ [following]
(...)
root@ubuntu:/# wget www.github.com
(...)
HTTP request sent, awaiting response... 301 Moved Permanently
Location: https://github.com/ [following]
(...)
```

Go back to *the first terminal* and see:

```
POD                            NAME
ubuntu                         wikimedia.org
ubuntu                         www.wikimedia.org
ubuntu                         www.github.com
ubuntu                         github.com
```

We can see that each time our `wget` client connected to a different
server, our tracer caught the Server Name Indication requested.

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`, and
trigger the output as before:

```bash
$ kubectl gadget trace sni -o json
{"type":"debug","message":"tracer attached","node":"minikube","namespace":"default","pod":"ubuntu"}
{"type":"normal","node":"minikube","namespace":"default","pod":"ubuntu","name":"wikimedia.org"}
{"type":"normal","node":"minikube","namespace":"default","pod":"ubuntu","name":"www.wikimedia.org"}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod ubuntu
pod "ubuntu" deleted
```
