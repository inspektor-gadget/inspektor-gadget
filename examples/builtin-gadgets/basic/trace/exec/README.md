# trace exec example

This is a basic example showing how to use
[trace/exec](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/gadgets/trace/exec)
package to trace the creation of new processes in the host.

In this case, not filter is passed to the tracer, hence all the new
processes created on the host are traced.

## How to build

```bash
$ go build .
```

## How to run

```bash
$ sudo ./exec
A new "calico" process with pid 118594 was executed
A new "portmap" process with pid 118606 was executed
A new "bandwidth" process with pid 118611 was executed
A new "runc" process with pid 118616 was executed
A new "docker-init" process with pid 118623 was executed
^C
```
