# Custom Operator and `grpc` runtime

This example shows how to run a gadget in a remote instance of Inspektor Gadget
and how to get its output by implementing a custom operator.

### How to run

`ig` needs to be running in daemon mode in the same machine as this example:

```bash
$ sudo ig daemon --host tcp://127.0.0.1:8888
INFO[0000] starting Inspektor Gadget daemon at "tcp://127.0.0.1:8888"
```

Run the binary. In this root is not needed because the all privileged operations
are done by the `ig` process.

```bash
$ go run .
{"comm":"irqbalance","err":0,"fd":6,"flags":0,"fname":"/proc/interrupts","gid":0,"mntns_id":4026533158,"mode":0,"pid":1262,"timestamp":6114008072805,"uid":0}
{"comm":"irqbalance","err":0,"fd":6,"flags":0,"fname":"/proc/stat","gid":0,"mntns_id":4026533158,"mode":0,"pid":1262,"timestamp":6114008961935,"uid":0}
{"comm":"irqbalance","err":0,"fd":6,"flags":0,"fname":"/proc/irq/65/smp_affinity","gid":0,"mntns_id":4026533158,"mode":0,"pid":1262,"timestamp":6114009113261,"uid":0}
{"comm":"irqbalance","err":0,"fd":6,"flags":0,"fname":"/proc/irq/98/smp_affinity","gid":0,"mntns_id":4026533158,"mode":0,"pid":1262,"timestamp":6114009138809,"uid":0}
```
