# `trace_dns`

This example shows how to run the `trace_dns` gadget and print the events it
captures to the terminal in json format.

### How to run

```bash
$ go run -exec sudo .
```

In another terminal, perform some DNS queries within a container. Queries on the
host aren't traced by the example.

```bash
$ docker run --name c3 --rm -it busybox sh -c "nslookup inspektor-gadget.io"
Server:         190.248.0.7
Address:        190.248.0.7:53

Non-authoritative answer:
Name:   inspektor-gadget.io
Address: 172.67.166.105
Name:   inspektor-gadget.io
Address: 104.21.11.160

Non-authoritative answer:
Name:   inspektor-gadget.io
Address: 2606:4700:3030::6815:ba0
Name:   inspektor-gadget.io
Address: 2606:4700:3037::ac43:a669
```

Those will be printed in the gadget's terminal:

```bash
$ go run -exec sudo .
{
  "anaddr": "00000000000000000000000000000000",
  "anaddrcount": 0,
  "ancount": 0,
  "gid": 0,
  "id": 64864,
  "k8s": {
    "container": "",
    "hostnetwork": false,
    "namespace": "",
    "node": "",
    "pod": ""
  },
  "latency_ns": 0,
  "mntns_id": 4026535114,
  "name": "inspektor-gadget.io",
  "netns": 4026535118,
  "pid": 125928,
  "pkt_type": 4,
  "qr": 0,
  "qtype": 1,
  "rcode": 0,
  "runtime": {
    "containerId": "1ccee3e25641f6825fe269628b2fb15de8e9e11b8dc8d5b01b6373839a140c62",
    "containerImageDigest": "",
    "containerImageName": "busybox",
    "containerName": "c3",
    "runtimeName": "docker"
  },
  "task": "nslookup",
  "tid": 125928,
  "timestamp": 8772942863578,
  "uid": 0
}
{
  "anaddr": "00000000000000000000000000000000",
  "anaddrcount": 0,
  "ancount": 0,
  "gid": 0,
  "id": 25747,
  "k8s": {
    "container": "",
    "hostnetwork": false,
    "namespace": "",
    "node": "",
    "pod": ""
  },
  "latency_ns": 0,
  "mntns_id": 4026535114,
  "name": "inspektor-gadget.io",
  "netns": 4026535118,
  "pid": 125928,
  "pkt_type": 4,
  "qr": 0,
  "qtype": 28,
  "rcode": 0,
  "runtime": {
    "containerId": "1ccee3e25641f6825fe269628b2fb15de8e9e11b8dc8d5b01b6373839a140c62",
    "containerImageDigest": "",
    "containerImageName": "busybox",
    "containerName": "c3",
    "runtimeName": "docker"
  },
  "task": "nslookup",
  "tid": 125928,
  "timestamp": 8772942906128,
  "uid": 0
}
{
  "anaddr": "00000000000000000000ffff68150ba0",
  "anaddrcount": 1,
  "ancount": 2,
  "gid": 0,
  "id": 64864,
  "k8s": {
    "container": "",
    "hostnetwork": false,
    "namespace": "",
    "node": "",
    "pod": ""
  },
  "latency_ns": 60238431,
  "mntns_id": 4026535114,
  "name": "inspektor-gadget.io",
  "netns": 4026535118,
  "pid": 125928,
  "pkt_type": 0,
  "qr": 1,
  "qtype": 1,
  "rcode": 0,
  "runtime": {
    "containerId": "1ccee3e25641f6825fe269628b2fb15de8e9e11b8dc8d5b01b6373839a140c62",
    "containerImageDigest": "",
    "containerImageName": "busybox",
    "containerName": "c3",
    "runtimeName": "docker"
  },
  "task": "nslookup",
  "tid": 125928,
  "timestamp": 8773003102009,
  "uid": 0
}
```

> [!WARNING]
> The DNS name isn't shown in the right format. See
> https://github.com/inspektor-gadget/inspektor-gadget/issues/2316.
