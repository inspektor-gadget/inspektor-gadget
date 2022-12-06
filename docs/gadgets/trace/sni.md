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
NODE             NAMESPACE        POD              NAME
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
NODE             NAMESPACE        POD              NAME
minikube         default          ubuntu           wikimedia.org
minikube         default          ubuntu           www.wikimedia.org
minikube         default          ubuntu           www.github.com
minikube         default          ubuntu           github.com
```

We can see that each time our `wget` client connected to a different
server, our tracer caught the Server Name Indication requested.

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the pod you created:

```bash
$ kubectl delete pod ubuntu
pod "ubuntu" deleted
```
