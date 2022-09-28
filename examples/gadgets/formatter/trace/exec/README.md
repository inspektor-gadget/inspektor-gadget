# trace exec example (with filter and formatter)

This example shows how to use different packages to create an
application to trace the process creation filtering by containers, using
an event formatter to print the events in a column format.

This is is a continuation of
[trace/exec/withfilter](../../../withfilter/trace/exec/).

## How to build

```bash
$ go build .
```

## How to run

Start the tracer in a terminal.

```bash
$ sudo ./exec --container name foo
```

Create a `foo` container in another terminal:

```bash
$ sudo docker run --rm --name foo ubuntu bash -c "cat /dev/null && sleep 2"
```

The first terminal will print the processes created inside the new
container. It's important to notice that even the first processes in the
container are traced, bash in this case.

```bash
$ sudo ./exec --containername foo
CONTAINER                             PID        PPID       COMM             RET ARGS
foo                                   33872      33821      bash             0   /usr/bin/bash -c cat /dev/null && sleep 2
foo                                   33915      33872      cat              0   /usr/bin/cat /dev/null
foo                                   33872      33821      sleep            0   /usr/bin/sleep 2
```
