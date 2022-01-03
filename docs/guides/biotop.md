---
title: 'The "biotop" gadget'
weight: 10
---

The biotop gadget allows us to see block device I/O on node(s).

The gadget doesn't support the following flags:
 * `--containername`
 * `--podname`
 * `--namespace`
 * `--output`

```bash
$ kubectl gadget biotop --node ip-10-0-30-247 --all-namespaces

14:28:17 loadavg: 0.53 0.32 0.34 8/528 43043

PID    COMM             D MAJ MIN DISK       I/O  Kbytes  AVGms
1860   etcd             W 253 0   vda          3      24   0.38
```

We can leave the monitoring with Ctrl-C.
