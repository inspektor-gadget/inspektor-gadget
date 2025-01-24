# Mutating fields from a `datasource`

This example shows how an operator can add and mutate fields from a datasource.

### How to compile

```bash
$ go build .
```

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
PID      UID      GID      MNTNS… E… FD      F… MODE    COMM    FNAME          IS_ROOT
...
128675   1001     1001     402653  0 3       52 0       cat     /etc/ld.so.cac false
128675   1001     1001     402653  0 3       52 0       cat     /lib/x86_64-li false
128675   1001     1001     402653  0 3       52 0       cat     /usr/lib/local false
128675   1001     1001     402653  0 3       0  0       cat     /dev/null      false
18740    1001     1001     402653  0 12      0  0       tmux: s /proc/124706/c false
7402     1001     1001     402653  0 47      19 384     Chrome_ /dev/shm/.com. false
1101     108      117      402653  0 7       52 0       systemd /proc/meminfo  false
1296     0        998      402653  0 21      0  0       wdavdae /proc/128676/s true
1296     0        998      402653  0 21      0  0       wdavdae /proc/128676/c true
1296     0        998      402653  0 21      0  0       wdavdae /proc/128676/s true
1296     0        998      402653  0 21      0  0       wdavdae /proc/128676/s true
1296     0        998      402653  0 21      0  0       wdavdae /proc/128676/c true
...
```
