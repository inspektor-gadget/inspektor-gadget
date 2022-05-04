---
title: 'Using profile block-io'
weight: 20
description: >
  Analyze block I/O performance through a latency distribution.
---

The profile block-io gadget gathers information about the usage of the
block device I/O (disk I/O), generating a histogram distribution of I/O
latency (time), when the gadget is stopped.

Notice that the latency of the disk I/O is measured from when the call is
issued to the device until its completion, it does not include time spent
in the kernel queue. This means that the histogram reflects only the
performance of the device and not the effective latency suffered by the
applications.

The histogram shows the number of I/O operations (`count` column) that lie in
the latency range `interval-start` -> `interval-end` (`usecs` column), which,
as the columns name indicates, is given in microseconds.

For this guide, we will use
[the `stress` tool](https://linux.die.net/man/1/stress) that allows us to load
and stress the system in many different ways. In particular, we will use
the `--io` flag that will generate a given number of workers to spin on the
[sync() syscall](https://man7.org/linux/man-pages/man2/sync.2.html). In this
way, we will generate disk I/O that we will analyse using the biolatency
gadget.

Firstly, let's use the profile block-io gadget to see the I/O latency in our
testing node with its normal load work:

```bash
# Run the gadget on the worker-node node
$ kubectl gadget profile block-io --node worker-node
Tracing block device I/O... Hit Ctrl-C to end

# Wait for around 1 minute and hit Ctrl+C to stop the gadget and see the results
^C

     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 0        |                                        |
        32 -> 63         : 17       |*                                       |
        64 -> 127        : 261      |*******************                     |
       128 -> 255        : 546      |****************************************|
       256 -> 511        : 426      |*******************************         |
       512 -> 1023       : 227      |****************                        |
      1024 -> 2047       : 18       |*                                       |
      2048 -> 4095       : 8        |                                        |
      4096 -> 8191       : 23       |*                                       |
      8192 -> 16383      : 15       |*                                       |
     16384 -> 32767      : 2        |                                        |
     32768 -> 65535      : 1        |                                        |
```

This output shows that the bulk of the I/O was between 64 and 1023 us, and
that there were 1544 I/O operations during the time the gadget was running.
Notice that we waited for 1 minute but longer time would produce more
stable results.

Now, let's increase the I/O operations using the stress tool:

```bash
# Start by creating our testing namespace
$ kubectl create ns test-biolatency

# Run stress with 1 worker that will generate I/O operations
$ kubectl run --restart=Never --image=polinux/stress stress-io -n test-biolatency -- stress --io 1
$ kubectl wait --timeout=-1s -n test-biolatency --for=condition=ready pod/stress-io
pod/stress-io condition met
$ kubectl get pod -n test-biolatency -o wide
NAME        READY   STATUS    RESTARTS   AGE   IP           NODE          NOMINATED NODE   READINESS GATES
stress-io   1/1     Running   0          2s    10.244.1.7   worker-node   <none>           <none>
```

Using the profile block-io gadget, we can generate another histogram to analyse the
disk I/O with this load:

```bash
# Run the gadget again
$ kubectl gadget profile block-io --node worker-node
Tracing block device I/O... Hit Ctrl-C to end

# Wait again for 1 minute and hit Ctrl+C to stop the gadget and see the results
^C

     usecs               : count     distribution
         0 -> 1          : 0        |                                        |
         2 -> 3          : 0        |                                        |
         4 -> 7          : 0        |                                        |
         8 -> 15         : 0        |                                        |
        16 -> 31         : 411      |                                        |
        32 -> 63         : 310822   |****************************************|
        64 -> 127        : 293404   |*************************************   |
       128 -> 255        : 194881   |*************************               |
       256 -> 511        : 96520    |************                            |
       512 -> 1023       : 33756    |****                                    |
      1024 -> 2047       : 4414     |                                        |
      2048 -> 4095       : 1007     |                                        |
      4096 -> 8191       : 1025     |                                        |
      8192 -> 16383      : 176      |                                        |
     16384 -> 32767      : 13       |                                        |
     32768 -> 65535      : 7        |                                        |
     65536 -> 131071     : 0        |                                        |
    131072 -> 262143     : 0        |                                        |
    262144 -> 524287     : 1        |                                        |
    524288 -> 1048575    : 0        |                                        |
   1048576 -> 2097151    : 1        |                                        |

# Remove load
$ kubectl delete pod/stress-io -n test-biolatency
```

The new histogram shows how the number of I/O operations increased
significantly, passing from 1544 (normal load) to 936438 (stressing the I/O).
On the other hand, even though this histogram shows that the bulk of the I/O
was still lower than 1023us, we can observe that there were several I/O
operations that suffered a high latency due to the load, one of them,
even more than 1 sec.

Delete the demo test namespace:
```bash
$ kubectl delete ns test-biolatency
namespace "test-biolatency" deleted
```

For further details, please refer to
[the BCC documentation](https://github.com/iovisor/bcc/blob/master/tools/biolatency_example.txt).
