---
title: 'Using `trace tcp`'
weight: 10
---

The `tcp` gadget is used to monitor tcp connections.

## How to use it?

First, we need to create one pod:

```bash
$ kubectl run busybox --image busybox:latest sleep inf
pod/busybox created
```

You can now use the gadget, but output will be empty:

```bash
$ kubectl gadget trace tcp
NODE             NAMESPACE        POD              CONTAINER        KPID   KCOMM            PAGES  TPID             TCOMM
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

The printed lined correspond to TCP connection established with the socket.
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

So, the above line should be read like this: "Command `wget`, which has PID 19981, established a TCP connection through IP version 4, using the `connect()` system call, from address 172.17.0.3 and port 16266 towards address 188.114.97.3 and port 433"

Note that, IP 188.114.97.3 corresponds to `kinvolk.io` while port 443 is the port generally used for HTTPS.

## Only print some information

You can restrain the information printed using `-o custom-columns=column0,...,columnN`.
This command will only show the PID and command:

```bash
$ kubectl gadget trace tcp -A -o custom-columns=pid,comm
PID    COMM
28489  wget
```

The following command is the same as default printing:

```bash
$ kubectl gadget trace tcp -A -o custom-columns=node,namespace,container,pod,t,pid,comm,ip,saddr,daddr,sport,dport
NODE             NAMESPACE        CONTAINER        POD              T PID    COMM             IP  SADDR            DADDR            SPORT   DPORT
minikube         <>               <>               <>               C 16266  wget             4   172.17.0.3       188.114.97.3     34878   443
```

## Use JSON output

This gadget supports JSON output, for this simply use `-o json`:

```bash
$ kubectl gadget trace tcp -o json
{"type":"normal","node":"minikube","namespace":"\u003c\u003e","pod":"\u003c\u003e","container":"\u003c\u003e","pid":16734,"comm":"wget","ipversion":4,"saddr":"172.17.0.3","daddr":"188.114.97.3","sport":35186,"dport":443,"operation":"connect"}
# You can use jq to make the output easier to read:
$ kubectl gadget trace tcp -o json | jq
{
  "type": "normal",
  "node": "minikube",
  "namespace": "<>",
  "pod": "<>",
  "container": "<>",
  "pid": 16734,
  "comm": "wget",
  "ipversion": 4,
  "saddr": "172.17.0.3",
  "daddr": "188.114.97.3",
  "sport": 35186,
  "dport": 443,
  "operation": "connect"
}
```

## Clean everything

Congratulations! You reached the end of this guide!
You can now delete the resource we created:

```bash
$ kubectl delete pod busybox
pod "busybox" deleted
```
