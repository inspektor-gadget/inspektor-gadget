---
title: 'Using snapshot socket'
weight: 20
description: >
  Gather information about TCP and UDP sockets.
---

The snapshot socket gadget gathers information about TCP and UDP sockets.

### On Kubernetes

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
NODE            NAMESPACE            POD       COMM  PID     PROTOCOL IP LOCAL      REMOTE    STATUS
minikube-docker test-socketcollector nginx-app nginx 1624436 TCP      4  0.0.0.0:80 0.0.0.0:0 LISTEN
minikube-docker test-socketcollector nginx-app nginx 1624436 TCP      6  :::80      :::0      LISTEN
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
NODE            NAMESPACE            POD       COMM  PID     PROTOCOL IP LOCAL        REMOTE    STATUS
minikube-docker test-socketcollector nginx-app nginx 1624436 TCP      4  0.0.0.0:8080 0.0.0.0:0 LISTEN
minikube-docker test-socketcollector nginx-app nginx 1624436 TCP      6  :::80        :::0      LISTEN
```

To get additional information, like the socket inode number, use the `-o columns=` flag:

```bash
$ kubectl-gadget snapshot socket -n test-socketcollector -o columns=container,comm,ppid,pid,uid,gid,inode,protocol,ip,local,remote,status
CONTAINER COMM  PPID    PID     UID GID INODE    PROTOCOL IP LOCAL        REMOTE    STATUS
nginx-app nginx 1624418 1624436 0   0   43480062 TCP      4  0.0.0.0:8080 0.0.0.0:0 LISTEN
nginx-app nginx 1624418 1624436 0   0   43368899 TCP      6  :::80        :::0      LISTEN
```

To see all the fields, use `-o yaml`:

```
$ kubectl gadget snapshot socket -n test-socketcollector -o yaml
---
- comm: nginx
  container: nginx-app
  gid: 0
  inodeNumber: 43480062
  ipversion: 4
  localAddress: 0.0.0.0
  localPort: 8080
  mountnsid: 4026534865
  namespace: test-socketcollector
  netnsid: 4026535078
  node: minikube-docker
  pid: 1624436
  pod: nginx-app
  ppid: 1624418
  protocol: TCP
  remoteAddress: 0.0.0.0
  remotePort: 0
  status: LISTEN
  type: normal
  uid: 0
- comm: nginx
  container: nginx-app
  gid: 0
  inodeNumber: 43368899
  ipversion: 6
  localAddress: '::'
  localPort: 80
  mountnsid: 4026534865
  namespace: test-socketcollector
  netnsid: 4026535078
  node: minikube-docker
  pid: 1624436
  pod: nginx-app
  ppid: 1624418
  protocol: TCP
  remoteAddress: '::'
  remotePort: 0
  status: LISTEN
  type: normal
  uid: 0
```

Delete test namespace:

```bash
$ kubectl delete ns test-socketcollector
namespace "test-socketcollector" deleted
```

### With `ig`

Start a docker container with a few UDP and TCP sockets:
```bash
$ docker run -ti --rm --name socket_test --privileged busybox
/ # echo 0 > /proc/sys/net/ipv6/conf/all/disable_ipv6
/ # nc -lk 127.0.0.1 -p 8081 &
/ # nc -lk ::1 -p 8082 &
/ # nc -u -lk 127.0.0.1 -p 8083 &
/ # nc -u -lk ::1 -p 8084 &
/ # nc 127.0.0.1 8081 &
/ # nc ::1 8082 &
/ # nc -u 127.0.0.1 8083 &
/ # nc -u ::1 8084 &
```

We can see the sockets with the `ig snapshot socket` command:

```bash
$ sudo ig snapshot socket -r docker -c socket_test -F comm:nc
CONTAINER   COMM PID     PROTOCOL IP LOCAL           REMOTE          STATUS
socket_test nc   1677151 TCP      4  127.0.0.1:8081  127.0.0.1:44015 ESTABLISHED
socket_test nc   1678747 TCP      4  127.0.0.1:44015 127.0.0.1:8081  ESTABLISHED
socket_test nc   1677365 TCP      6  ::1:8082        ::1:37117       ESTABLISHED
socket_test nc   1679491 TCP      6  ::1:37117       ::1:8082        ESTABLISHED
socket_test nc   1677957 UDP      4  127.0.0.1:8083  127.0.0.1:0     ACTIVE
socket_test nc   1680039 UDP      4  127.0.0.1:57042 127.0.0.1:8083  ACTIVE
socket_test nc   1678099 UDP      6  ::1:8084        ::1:0           ACTIVE
socket_test nc   1680619 UDP      6  ::1:59868       ::1:8084        ACTIVE

```