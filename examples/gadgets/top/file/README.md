# top file example

This is example shows how to use
[top/file](https://github.com/kinvolk/inspektor-gadget/tree/main/pkg/gadgets/top/file)
package to get a list of the files with a higher number of write
operations on the host.

## How to build

```bash
$ go build .
```

## How to run

```bash
$ sudo ./file
The 5 files with more write operations in the last 1 seconds are:
[1]: db
[2]: 0000000000000060-00000000006b423e.wal
[3]: namespace
[4]: cpuset.mems
[5]: cpuset.sched_relax_domain_level
---
The 5 files with more write operations in the last 1 seconds are:
[1]: syslog
[2]: libpthread-2.33.so
[3]: cpuacct.usage
[4]: cpuacct.usage_percpu
[5]: sessionid
---
The 5 files with more write operations in the last 1 seconds are:
[1]: db
[2]: syslog
[3]: 0000000000000060-00000000006b423e.wal
[4]: 0000000000000060-00000000006b423e.wal
[5]: 327548445572411dcfc2485386aa94c43d63d1bb6f15a72f9581ba83593b4c1a
---
^C
```
