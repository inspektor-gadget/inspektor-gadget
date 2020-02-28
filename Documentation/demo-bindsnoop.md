# Inspektor Gadget demo: the "bindsnoop" gadget

bindsnoop reports socket options set before the bind call that would impact
this system call behavior. It comes from the [bcc bindsnoop
tool](https://github.com/iovisor/bcc/blob/master/tools/bindsnoop_example.txt)
and displays the same output.

In one terminal, start the bindsnoop gadget:
```
$ inspektor-gadget bindsnoop --label run=nginx-app
```

In another terminal, start nginx:
```
$ kubectl run --generator=run-pod/v1 --image=nginx nginx-app --port=80
pod/nginx-app created
```

When nginx starts, it binds on the TCP port 80. Inspektor Gadget will detect it
and display the following output:

```
[ 1] Tracing binds ... Hit Ctrl-C to end
[ 1]      PID COMM         PROT ADDR            PORT   OPTS IF
[ 1]    18411 nginx        TCP  0.0.0.0            80 ...R.  0
```
