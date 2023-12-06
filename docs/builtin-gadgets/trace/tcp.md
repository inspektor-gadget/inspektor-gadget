---
title: 'Using trace tcp'
weight: 20
description: >
  Trace tcp connect, accept and close.
---

The trace tcp gadget can be used to monitor tcp connections, as it shows
connect, accept and close events related to TCP connections.

### On Kubernetes

First, we need to create one pod:

```bash
$ kubectl run bb --image busybox:latest sleep inf
pod/bb created
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace tcp
K8S.NODE            K8S.NAMESPACE       K8S.POD             K8S.CONTAINER       T PID        COMM       IP SRC                DST               
```

Indeed, it is waiting for TCP connection to be established in the `default` namespace (you can use `-A` to monitor all namespaces and then be sure to not miss any event).
So, in *another terminal*, `exec` a container and run this `wget`:

```bash
$ kubectl exec -ti bb -- wget https://www.kinvolk.io
Connecting to www.kinvolk.io (188.114.96.3:443)
wget: note: TLS certificate validation not implemented
saving to 'index.html'
index.html           100% |************************************************************************************************| 47748  0:00:00 ETA
'index.html' saved

```

Go back to *the first terminal* and see:

```bash
K8S.NODE            K8S.NAMESPACE       K8S.POD             K8S.CONTAINER       T PID        COMM       IP SRC                DST               
minikube-docker     default             bb                  bb                  C 253124     wget       4  p/default/bb:50192 o/188.114.96.3:443
```

The printed lines correspond to TCP connection established with the socket.
Here is the full legend of all the fields:

* `T`: How the TCP connection was established, it can be one of the following values:
	* `C`: The TCP connection was established after a `connect()` system call.
	* `A`: The TCP connection was established after an `accept()` system call.
	* `X`: The TCP connection was closed following the `close()` system call.
	* `U`: The TCP connection was either established or closed following an unknown reason.
* `PID`: The PID which established the TCP connection.
* `COMM`: The command corresponding to the PID.
* `IP`: The IP version (either 4 or 6).
* `SRC`: The source IP address, pod namespace + pod name or service name together with the port
* `DST`: The destination IP address, pod namespace + pod name or service name together with the port

So, the above line should be read like this: "Command `wget`, with PID 253124, established a TCP connection through IP version 4, using the `connect()` system call, from the `busybox` container on port 50192 towards address 188.114.96.3 and port 433"

Note that, IP 188.114.96.3 corresponds to `kinvolk.io` while port 443 is the port generally used for HTTPS.

#### Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete pod busybox
pod "busybox" deleted
```

### With `ig`

With the following container we can see that the gadget shows that a
TCP connection was established.

Start the gadget:

```bash
$ sudo ig trace tcp -c test-trace-tcp
```

Then, run a container that creates a TCP connection.

```bash
$ docker run -it --rm --name test-trace-tcp busybox /bin/sh -c "wget https://www.example.com"
Connecting to www.example.com (93.184.216.34:443)
wget: note: TLS certificate validation not implemented
saving to 'index.html'
index.html           100% |********************************|  1256  0:00:00 ETA
'index.html' saved
```

The gadget will print that connection on the first terminal

```bash
$ sudo ig trace tcp -c test-trace-tcp
RUNTIME.CONTAINERNAME     T PID        COMM          IP SRC                      DST                     
test-trace-tcp            C 269349     wget          4  172.17.0.2:46502         93.184.216.34:443 
```
