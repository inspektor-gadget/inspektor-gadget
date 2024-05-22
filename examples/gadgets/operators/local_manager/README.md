# Local Manager Operator

This example shows how to use the `LocalManager` operator to filter and enrich
events with container information on the local host.


### How to run

```bash
$ go run -exec sudo .
```

The example is configured to only capture events from `mycontainer`. Run the
following commands in a different terminal:

```bash
$ docker run --name mycontainer --rm -it busybox sh -c "cat /dev/null"
$ docker run --name foocontainer --rm -it busybox sh -c "cat /dev/null"
```

The gadget only captured the events from `mycontainer`, and you can see how
they're enriched with the container name:

```bash
$ go run -exec sudo .
{"comm":"runc:[2:INIT]","err":0,"fd":4,"flags":524288,"fname":"/proc/self/fd","gid":0,"k8s":{"container":"","hostnetwork":false,"namespace":"","node":"","pod":""},"mntns_id":4026535204,"mode":0,"pid":317300,"runtime":{"containerId":"ba89979bd3ce494f4b997cac228185000598386fcb55aa9d0c236ccc203fe6a6","containerImageDigest":"","containerImageName":"busybox","containerName":"mycontainer","runtimeName":"docker"},"timestamp":34044622172785,"uid":0}

...
{"comm":"sh","err":0,"fd":3,"flags":524288,"fname":"/lib/libc.so.6","gid":0,"k8s":{"container":"","hostnetwork":false,"namespace":"","node":"","pod":""},"mntns_id":4026535204,"mode":0,"pid":317300,"runtime":{"containerId":"ba89979bd3ce494f4b997cac228185000598386fcb55aa9d0c236ccc203fe6a6","containerImageDigest":"","containerImageName":"busybox","containerName":"mycontainer","runtimeName":"docker"},"timestamp":34044623757047,"uid":0}
...
{"comm":"cat","err":0,"fd":3,"flags":0,"fname":"/dev/null","gid":0,"k8s":{"container":"","hostnetwork":false,"namespace":"","node":"","pod":""},"mntns_id":4026535204,"mode":0,"pid":317300,"runtime":{"containerId":"ba89979bd3ce494f4b997cac228185000598386fcb55aa9d0c236ccc203fe6a6","containerImageDigest":"","containerImageName":"busybox","containerName":"mycontainer","runtimeName":"docker"},"timestamp":34044624920207,"uid":0}
```
