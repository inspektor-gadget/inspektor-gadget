---
title: 'Using bring-your-own-bpf'
weight: 40
description: >
  Run your own BPF code
---

## With local-gadget

```
$ sudo GODEBUG=netdns=go ./local-gadget trace byob -r docker --oci-image="albantest.azurecr.io/bee-tcpconnect:dev2"
$ sudo GODEBUG=netdns=go ./local-gadget trace byob -r docker --oci-image="ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11"
$ sudo GODEBUG=netdns=go ./local-gadget trace byob -r docker --file ./pkg/gadgets/trace/byob/tracer/ebpf-testdata/tcpconnect_bpfel_x86.o
$ sudo GODEBUG=netdns=go ./local-gadget trace byob -r docker --file ./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ sudo GODEBUG=netdns=go ./local-gadget trace byob -r docker --file ./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```

Without recompiling:
```
$ go run -exec sudo ./cmd/local-gadget/... trace byob -r docker -o json --file ./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ go run -exec sudo ./cmd/local-gadget/... trace byob -r docker -o json --file ./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```

## With kubectl-gadget

```
$ kubectl gadget trace byob -o json --oci-image="ghcr.io/solo-io/bumblebee/tcpconnect:0.0.11"
$ kubectl gadget trace byob -o json --file=./pkg/gadgets/trace/byob/tracer/ebpf-testdata/tcpconnect_bpfel_x86.o
$ kubectl gadget trace byob -o json --file=./pkg/gadgets/trace/byob/tracer/ebpf-testdata/http_bpfel.o
$ kubectl gadget trace byob -o json --file=./pkg/gadgets/trace/byob/tracer/ebpf-testdata/dns_bpfel.o
```

## How to write your own BPF

...
