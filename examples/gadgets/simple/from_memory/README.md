# Embedding a gadget image within the application

This example shows how a gadget image can be embedded in the application binary
and how it can be run from there.

The `trace_open.tar` file was created with:

```bash
$ sudo ig image export trace_open:latest trace_open.tar
```

### How to compile

```bash
$ go build .
```

### How to run

The compiled binary doesn't need any parameters, just run it with root permissions:

```bash
$ sudo ./from_memory
```

The gadget runs successfully.

```bash
$ sudo ./from_memory
TIMESTAMP          PID      UID      GID      MNTNS… E… FD       FL… MODE    COMM    FNAME
33760132075419     308204   0        0        402653  0 23       524 0       from_me /sys/kernel/tra
33760214948931     1101     108      117      402653  0 7        524 0       systemd /proc/meminfo
33760215059910     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
33760215123230     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
33760215153988     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
33760215186640     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
33760215219722     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
33760215251071     1101     108      117      402653  0 7        524 0       systemd /sys/fs/cgroup/
```
