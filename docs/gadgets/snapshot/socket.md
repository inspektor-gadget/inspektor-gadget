---
title: 'Using snapshot socket'
weight: 20
description: >
  Gather information about TCP and UDP sockets.
---

The snapshot socket gadget gathers information about TCP and UDP sockets.

We will start this demo by using nginx to create a web server on port 80:

```bash
$ kubectl create ns test-socketcollector
namespace/test-socketcollector created
$ kubectl run --restart=Never -n test-socketcollector --image=nginx nginx-app --port=80
pod/nginx-app created
```

Wait for the pod to get ready:

```bash
$ kubectl wait --timeout=-1s -n test-socketcollector --for=condition=ready pod/nginx-app ; kubectl get pod -n test-socketcollector
pod/nginx-app condition met
NAME        READY   STATUS    RESTARTS   AGE
nginx-app   1/1     Running   0          46s
```

We will now use the snapshot socket gadget to retrieve the TCP/UDP sockets information
of the nginx-app pod. Notice we are filtering by namespace but we could have
done it also using the podname or labels:

```bash
$ kubectl gadget snapshot socket -n test-socketcollector
NODE       NAMESPACE               POD          PROTOCOL    LOCAL         REMOTE       STATUS
my-node    test-socketcollector    nginx-app    TCP         0.0.0.0:80    0.0.0.0:0    LISTEN
```

In the output, "LOCAL" is the local IP address and port number pair.
If connected, "REMOTE" is the remote IP address and port number pair,
otherwise, it will be "0.0.0.0:0". While "STATUS" is the internal
status of the socket.

Now, modify the nginx configuration to listen on port 8080 instead of 80 and reload the daemon:

```bash
$ kubectl exec -n test-socketcollector nginx-app -- /bin/bash -c "sed -i 's/listen \+80;/listen\t8080;/g' /etc/nginx/conf.d/default.conf && exec nginx -s reload"
[...] signal process started
```

Now, we can check again with the snapshot socket gadget what the active socket is:

```bash
$ kubectl gadget snapshot socket -n test-socketcollector
NODE       NAMESPACE               POD          PROTOCOL    LOCAL           REMOTE       STATUS
my-node    test-socketcollector    nginx-app    TCP         0.0.0.0:8080    0.0.0.0:0    LISTEN
```

To get extended information, like the socket inode number, just the `-e` or `--extend` flag:

```bash
$ kubectl gadget snapshot socket -n test-socketcollector -e
NODE       NAMESPACE               POD          PROTOCOL    LOCAL           REMOTE       STATUS         INODE
my-node    test-socketcollector    nginx-app    TCP         0.0.0.0:8080    0.0.0.0:0    LISTEN         716174
```

Delete test namespace:

```bash
$ kubectl delete ns test-socketcollector
namespace "test-socketcollector" deleted
```
