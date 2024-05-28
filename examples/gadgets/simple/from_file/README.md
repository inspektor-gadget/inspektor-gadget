# Run a gadget from file

This example shows how to run a gadget from a file.

The `trace_open.tar` file was created with:

```bash
$ sudo -E ig image export trace_open:latest trace_open.tar
```

### How to compile

```bash
$ go build .
```

### How to run

The compiled binary doesn't need any parameters, just run it with root permissions:

```bash
$ sudo ./from_file
```

The gadget runs successfully.

```bash
$ sudo ./from_file
TIMESTAMP           PID       UID       GID       MNTNS_… E… FD       F… MODE     COMM     FNAME
32127308423053      158878    1001      1001      4026531  0 14       0  0        gnome-sy /proc/stat
32127308708823      158878    1001      1001      4026531  0 14       0  0        gnome-sy /proc/meminfo
32127308755030      158878    1001      1001      4026531  0 14       0  0        gnome-sy /proc/meminfo
32127308787041      158878    1001      1001      4026531  0 14       0  0        gnome-sy /proc/vmstat
32127308939499      158878    1001      1001      4026531  0 14       0  0        gnome-sy /proc/net/dev
32127309134858      158878    1001      1001      4026531  0 14       0  0        gnome-sy /sys/class/net/lo
32127309170575      158878    1001      1001      4026531  0 14       0  0        gnome-sy /sys/class/net/lo
32127309198077      158878    1001      1001      4026531  0 14       0  0        gnome-sy /sys/class/net/lo
32127309225119      158878    1001      1001      4026531  0 14       0  0        gnome-sy /sys/class/net/lo
32127309251508      158878    1001      1001      4026531  0 14       0  0        gnome-sy /sys/class/net/lo
...
```
