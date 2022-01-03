---
title: local-gadget
weight: 80
description: >
  How to use the local-gadget tool.
---

Inspektor Gadget can also be used without Kubernetes to trace containers with the local-gadget tool.

## Examples

### biolatency

```bash
$ sudo ./local-gadget
» create biolatency trace1
» operation trace1 stop
State: Completed
Tracing block device I/O... Hit Ctrl-C to end.

     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 1        |                                        |
        32 -> 63         : 13       |*****                                   |
        64 -> 127        : 37       |***************                         |
       128 -> 255        : 27       |***********                             |
       256 -> 511        : 17       |*******                                 |
       512 -> 1023       : 14       |*****                                   |
      1024 -> 2047       : 2        |                                        |
      2048 -> 4095       : 95       |****************************************|
      4096 -> 8191       : 6        |**                                      |
```

### dns

Start the DNS gadget:

```bash
$ sudo ./local-gadget 
» create dns trace1 --container-selector shell01
» stream trace1 -f
{"notice":"tracer attached","node":"local","namespace":"default","pod":"shell01"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pkt_type":"OUTGOING"}
{"node":"local","namespace":"default","pod":"shell01","name":"www.wikipedia.org.","pkt_type":"OUTGOING"}
{"notice":"tracer detached","node":"local","namespace":"default","pod":"shell01"}
```

Start a container:

```bash
$ docker run -ti --rm --name shell01 busybox wget wikipedia.org
```

### seccomp

```bash
$ sudo ./local-gadget
» create seccomp trace1 --container-selector shell01 --output-mode Status
```

Start a container:

```bash
$ docker run -ti --rm --name shell01 busybox
```

Resume from the local-gadget terminal:

```bash
» operation trace1 generate
State: Started
{
  "defaultAction": "SCMP_ACT_ERRNO",
  "architectures": [
    "SCMP_ARCH_X86_64",
    "SCMP_ARCH_X86",
    "SCMP_ARCH_X32"
  ],
  "syscalls": [
    {
      "names": [
        "arch_prctl",
        "brk",
        "close",
        "fcntl",
        "getcwd",
        "geteuid",
        "getpgrp",
        "getpid",
        "getppid",
        "getuid",
        "ioctl",
        "open",
        "poll",
        "read",
        "rt_sigaction",
        "rt_sigreturn",
        "setpgid",
        "write"
      ],
      "action": "SCMP_ACT_ALLOW"
    }
  ]
}
```
