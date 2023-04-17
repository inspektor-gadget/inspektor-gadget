---
title: 'Using run (bring-your-own-bpf)'
weight: 20
description: >
  Run your own eBPF code
---

The `run` gadget launches custom eBPF that can be used with Inspektor Gadget.
There are currently two options for loading your own eBPF code:
1. OCI image URL as an argument. This utlizes the [Bumblebee project from solo.io](https://github.com/solo-io/bumblebee) which, amongst other things, packages your eBPF into OCI images.
2. `--prog`
   allows you to directly reference the compiled eBPF code. And should only be used for development

## TODO: How to write your own BPF

...

Also mention the socketenrichment/integration with IG

output is always ringbuffer/perfbuffer

## On Kubernetes

```bash
$ kubectl gadget run -o json ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11
$ kubectl gadget run -o json --prog=@./pkg/gadgets/trace/run/ebpf-testdata/tcpconnect_bpfel_x86.o
$ kubectl gadget run -o json --prog=@./pkg/gadgets/trace/run/ebpf-testdata/http_bpfel.o
$ kubectl gadget run -o json --prog=@./pkg/gadgets/trace/run/ebpf-testdata/dns_bpfel.o
```

## With `ig`

``` bash
$ sudo GODEBUG=netdns=go ./ig run -r docker albantest.azurecr.io/bee-tcpconnect:dev2
$ sudo GODEBUG=netdns=go ./ig run -r docker ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11
$ sudo GODEBUG=netdns=go ./ig run -r docker --prog @./pkg/gadgets/run/tracer/ebpf-testdata/tcpconnect_bpfel_x86.o
$ sudo GODEBUG=netdns=go ./ig run -r docker --prog @./pkg/gadgets/run/tracer/ebpf-testdata/http_bpfel.o
$ sudo GODEBUG=netdns=go ./ig run -r docker --prog @./pkg/gadgets/run/tracer/ebpf-testdata/dns_bpfel.o
```

Without recompiling:
```bash
$ go run -exec sudo ./cmd/ig/... run -r docker -o json --prog @./pkg/gadgets/run/tracer/ebpf-testdata/http_bpfel.o
$ go run -exec sudo ./cmd/ig/... run -r docker -o json --prog @./pkg/gadgets/run/tracer/ebpf-testdata/dns_bpfel.o
```
