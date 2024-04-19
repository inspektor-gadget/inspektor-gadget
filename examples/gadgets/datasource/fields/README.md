# Getting Specific Fields from a `datasource`

This example shows how to get some specific fields from the event by using the
data source.

### How to run

```bash
$ go run -exec sudo .
```

In another terminal, open some files

```bash
$ cat /dev/null
```

Those will be printed in the gadget's terminal:

```bash
$ go run -exec sudo .
...
command cat (143535) opened /etc/ld.so.cache
command cat (143535) opened /lib/x86_64-linux-gnu/libc.so.6
command cat (143535) opened /usr/lib/locale/locale-archive
command cat (143535) opened /dev/null
...
```
