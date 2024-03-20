# trace network example (with filter)

This example shows how to use different packages to create an application to
trace network connections filtering by containers. Beyond that, network events
are enriched with Kubernetes IP addresses and Kubernetes destinations, e.g. pod
or service names.

## How to build

```bash
$ go build .
```

## How to run in a terminal

```bash
$ sudo ./network
failed to initialize kube IP enricher: creating k8s inventory cache: creating new k8s clientset: stat /root/.kube/config: no such file or directory. It won't be available.
failed to initialize kube name enricher: creating k8s inventory cache: creating new k8s clientset: stat /root/.kube/config: no such file or directory. It won't be available.
[...]
{
  "runtime": {
    "runtimeName": "containerd",
    "containerId": "e3bc6362dac572037f025f898b394c698c701e1dba753099459a1889b6ecd95b",
    "containerName": "coredns",
    "containerImageName": "registry.k8s.io/coredns/coredns:v1.10.1",
    "containerImageDigest": "sha256:a0ead06651cf580044aeb0a0feba63591858fb2e43ade8c9dea45a6a89ae7e5e"
  },
  "k8s": {
    "namespace": "kube-system",
    "podName": "coredns-5dd5756b68-wh964",
    "containerName": "coredns"
  },
  "timestamp": 1710410447833705750,
  "type": "normal",
  "mountnsid": 4026533116,
  "netnsid": 4026532725,
  "pid": 4955,
  "tid": 5150,
  "comm": "coredns",
  "uid": 0,
  "gid": 0,
  "pktType": "OUTGOING",
  "proto": "TCP",
  "port": 8080,
  "podHostIP": "172.16.184.153",
  "podIP": "192.168.160.244",
  "podOwner": "coredns",
  "podLabels": {
    "k8s-app": "kube-dns",
    "pod-template-hash": "5dd5756b68"
  },
  "dst": {
    "addr": "127.0.0.1",
    "version": 4,
    "kind": "raw"
  }
}
[...]
```

## How to deploy the DaemonSet

You can use a convenience script [deploy.sh](./deploy.sh). The `install`
command compiles example code to a container image, imports it to the `k8s.io`
containerd namespace, and finally creates the DaemonSet.

Notice however, that it works only on a cluster with containerd CRI and assumes
that the `ctr` command is in your PATH.

Otherwise, you must build and push the image to a container registry yourself
and possibly update the image reference in the [deploy.yaml](./deploy.yaml)
descriptor.

```
./deploy.sh install
```

Check that tracer runs on each Linux node:

```bash
$ kubectl get pod -n gadget-examples -l name=container-network-tracer
NAME                             READY   STATUS    RESTARTS   AGE
container-network-tracer-2wsh6   1/1     Running   0          39s
```

If everything goes well, you should see network events printed to the tracer's
logs output:

```bash
$ kubectl logs -n gadget-examples ds/container-network-tracer
[...]
{
  "runtime": {
    "runtimeName": "containerd",
    "containerId": "e3bc6362dac572037f025f898b394c698c701e1dba753099459a1889b6ecd95b",
    "containerName": "coredns",
    "containerImageName": "registry.k8s.io/coredns/coredns:v1.10.1",
    "containerImageDigest": "sha256:a0ead06651cf580044aeb0a0feba63591858fb2e43ade8c9dea45a6a89ae7e5e"
  },
  "k8s": {
    "namespace": "kube-system",
    "podName": "coredns-5dd5756b68-wh964",
    "containerName": "coredns"
  },
  "timestamp": 1710410447833705750,
  "type": "normal",
  "mountnsid": 4026533116,
  "netnsid": 4026532725,
  "pid": 4955,
  "tid": 5150,
  "comm": "coredns",
  "uid": 0,
  "gid": 0,
  "pktType": "OUTGOING",
  "proto": "TCP",
  "port": 8080,
  "podHostIP": "172.16.184.153",
  "podIP": "192.168.160.244",
  "podOwner": "coredns",
  "podLabels": {
    "k8s-app": "kube-dns",
    "pod-template-hash": "5dd5756b68"
  },
  "dst": {
    "addr": "127.0.0.1",
    "version": 4,
    "kind": "raw"
  }
}
[...]
```

To undeploy the DaemonSet:

```
./deploy uninstall
```
