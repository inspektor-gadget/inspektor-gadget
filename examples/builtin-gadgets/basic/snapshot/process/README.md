# snapshot process example

This example uses the
[snapshot/process](https://github.com/inspektor-gadget/inspektor-gadget/tree/main/pkg/gadgets/snapshot/process)
package to get a list of the running processes in the host.

## How to build

```bash
$ go build .
```

## How to run

```bash
$ sudo ./process
NAME                 PID
systemd                1
kthreadd               2
rcu_gp                 3
rcu_par_gp             4
kworker/0:0H           6
mm_percpu_wq           9
rcu_tasks_rude_       10
rcu_tasks_trace       11
ksoftirqd/0           12
rcu_sched             13
migration/0           14
idle_inject/0         15
cpuhp/0               16
cpuhp/1               17
idle_inject/1         18
migration/1           19
ksoftirqd/1           20
kworker/1:0H          22
cpuhp/2               23
idle_inject/2         24
migration/2           25
ksoftirqd/2           26
kworker/2:0H          28
[...]
```
