# trace exec example (with filter)

This example shows how to use different packages to create an
application to trace the process creation filtering by containers.

This is a more complex setup than the presented in
[trace/exec/basic](../../../basic/trace/exec) example. It also uses the container
collection package explained in the
[container-collection](../../../../container-collection/) example.

## How to build

```bash
$ go build .
```

## How to run

Start the tracer in a terminal.

```bash
$ sudo ./exec --containername foo
```

Create a `foo` container in another terminal:

```bash
$ sudo docker run --rm --name foo ubuntu bash -c "cat /dev/null && sleep 2"
```

The first terminal will print the processes created inside such a
container. It's important to notice that even the first processes in the
container are traced, bash in this case.

```bash
$ sudo ./exec --containername foo
A new "bash" process with pid 445451 was executed in container "foo"
A new "cat" process with pid 445512 was executed in container "foo"
A new "sleep" process with pid 445451 was executed in container "foo"
```
