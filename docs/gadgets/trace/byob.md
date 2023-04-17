---
title: 'Using bring-your-own-bpf'
weight: 20
description: >
  Run your own eBPF code
---

With the `byob` gadget launches custom eBPF can be used with Inspektor Gadget.
There are currently two options for loading your own eBPF code:
1. `--oci-image`
   This utlizes the [Bumblebee project from solo.io](https://github.com/solo-io/bumblebee) which, amongst other things, packages your eBPF into OCI images.
2. `--file`
   allows you to directly reference the compiled eBPF code.

## TODO: How to write your own BPF

...

Also mention the socketenrichment/integration with IG

output is always ringbuffer/perfbuffer

## On Kubernetes

```bash
$ kubectl gadget trace byob -o json --oci-image="ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11"
$ kubectl gadget trace byob -o json --file=@./pkg/gadgets/trace/byob/tracer/ebpf-testdata/tcpconnect_bpfel_x86.o
$ kubectl gadget trace byob -o json --file=@./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ kubectl gadget trace byob -o json --file=@./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```

## With `ig`

``` bash
$ sudo GODEBUG=netdns=go ./ig trace byob -r docker --oci-image="albantest.azurecr.io/bee-tcpconnect:dev2"
$ sudo GODEBUG=netdns=go ./ig trace byob -r docker --oci-image="ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11"
$ sudo GODEBUG=netdns=go ./ig trace byob -r docker --file @./pkg/gadgets/trace/byob/tracer/ebpf-testdata/tcpconnect_bpfel_x86.o
$ sudo GODEBUG=netdns=go ./ig trace byob -r docker --file @./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ sudo GODEBUG=netdns=go ./ig trace byob -r docker --file @./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```

Without recompiling:
```bash
$ go run -exec sudo ./cmd/ig/... trace byob -r docker -o json --file @./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ go run -exec sudo ./cmd/ig/... trace byob -r docker -o json --file @./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```
