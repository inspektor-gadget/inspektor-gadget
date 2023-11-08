---
title: 'Gadgets as OCI artifacts'
weight: 20
description: 'Reference documentation for the format of a gadget OCI artifact'
---

Intro TODO

## Specifications

The [Open Container Initiative](https://opencontainers.org/) defines the [Image
Format
Specification](https://github.com/opencontainers/image-spec/blob/main/spec.md).
This specification was initially defined for container images but it is
extended to store other artifacts, see [Guidance for Artifacts
Authors](https://github.com/opencontainers/image-spec/blob/main/artifacts-guidance.md).

## Architectures

Inspektor Gadget supports multi architecture artifacts. The following
architectures are supported:

- amd64
- arm64

## Gadget metadata

Media type: `application/vnd.gadget.config.v1+yaml`

The content has the type [GadgetMetadata
struct](https://github.com/inspektor-gadget/inspektor-gadget/blob/7d12644a89217bdbf861da54cd8bd2a370754ece/pkg/gadgets/run/types/metadata.go#L136).
It is a work in progress.

## Image layers and media types

Each architecture can contain several layers, but each layer must have a
different media type among the following:

- `application/vnd.gadget.ebpf.program.v1+binary`
- `application/vnd.gadget.wasm.program.v1+binary`

## Image labels

TODO
