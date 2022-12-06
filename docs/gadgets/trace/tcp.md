---
title: 'Using trace tcp'
weight: 20
description: >
  Trace tcp connect, accept and close.
---

The trace tcp gadget can be used to monitor tcp connections, as it shows
connect, accept and close events related to TCP connections.

## How to use it?

First, we need to create one pod:

```bash
$ kubectl run busybox --image busybox:latest sleep inf
pod/busybox created
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace tcp
NODE             NAMESPACE        POD              CONTAINER        T PID    COMM             IP  SADDR            DADDR            SPORT   DPORT
```

Indeed, it is waiting for TCP connection to be established in the `default` namespace (you can use `-A` to monitor all namespaces and then be sure to not miss any event).
So, in *another terminal*, `exec` a container and run this `wget`:

```bash
$ kubectl exec -ti busybox -- wget https://www.kinvolk.io
Connecting to www.kinvolk.io (188.114.97.3:443)
wget: note: TLS certificate validation not implemented
saving to 'index.html'
index.html           100% |*************************************************************************************************| 42627  0:00:00 ETA
'index.html' saved
```

Go back to *the first terminal* and see:

```bash
NODE             NAMESPACE        POD              CONTAINER        T PID    COMM             IP  SADDR            DADDR            SPORT   DPORT
minikube         <>               <>               <>               C 16266  wget             4   172.17.0.3       188.114.97.3     34878   443
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
* `SADDR`: The source IP address.
* `DADDR`: The destination IP address.
* `SPORT`: The source port.
* `DPORT`: The destination port.

So, the above line should be read like this: "Command `wget`, with PID 19981, established a TCP connection through IP version 4, using the `connect()` system call, from address 172.17.0.3 and port 16266 towards address 188.114.97.3 and port 433"

Note that, IP 188.114.97.3 corresponds to `kinvolk.io` while port 443 is the port generally used for HTTPS.

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete pod busybox
pod "busybox" deleted
```
