# CLI Operator

This example shows how to use the `CLI` operator to print events to the terminal
in a formatted way.

### How to run

```bash
$ go run -exec sudo .
```

In another terminal, open some files:

```bash
$ cat /dev/null
```

The output is printed using columns:

```bash
$ go run -exec sudo .
TIMESTAMP         PID      UID      GID      MNTNS… E… FD       F… MODE    COMM    FNAME
14197547080990    70855    0        0        402653  0 23       52 0       cli     /sys/kernel/tra
14197547104474    707      0        0        402653  2 0        52 0       systemd /run/log/journa
14197651817196    1101     108      117      402653  0 7        52 0       systemd /proc/meminfo
14197716625333    5432     1001     1001     402653  0 156      52 0       FSBroke /sys/devices/sy
14197761237164    3122     1001     1001     402653  0 37       2  0       dbus-da /sys/kernel/sec
14197901812855    1101     108      117      402653  0 7        52 0       systemd /proc/meminfo
14197901932502    1101     108      117      402653  0 7        52 0       systemd /sys/fs/cgroup/
14197901998005    1101     108      117      402653  0 7        52 0       systemd /sys/fs/cgroup
```
