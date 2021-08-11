---
title: 'The "bindsnoop" gadget'
weight: 10
---

bindsnoop reports socket options set before the bind call that would impact
this system call behavior. It comes from the [bcc bindsnoop
tool](https://github.com/iovisor/bcc/blob/master/tools/bindsnoop_example.txt)
and displays the same output.

In one terminal, start the bindsnoop gadget:
```
$ kubectl gadget bindsnoop --selector run=nginx-app
```

In another terminal, start nginx:
```
$ kubectl run --generator=run-pod/v1 --image=nginx nginx-app --port=80
pod/nginx-app created
```

When nginx starts, it binds on the TCP port 80. Inspektor Gadget will detect it
and display the following output:

```
Tracing binds ... Hit Ctrl-C to end
NODE             NAMESPACE        PODNAME          CONTAINERNAME        PID COMM         PROT ADDR            PORT   OPTS IF
ip-10-0-30-247   default          nginx-app        nginx-app         186667 nginx        UNKN 0.0.0.0            80 ...R.  0
```
