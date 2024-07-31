---
title: 'Gadgets as OCI artifacts'
sidebar_position: 20
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
- `application/vnd.gadget.btfgen.v1+binary`

### The ebpf layer

There must be exactly one layer with the ebpf media type. It must not be empty.
Its content must be a valid ELF file.

### The wasm layer

There must be at most one layer with the wasm media type. If present, it must
not be empty and it must be a valid wasm file.

### The btfgen layer

[btfgen](https://www.inspektor-gadget.io//blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/)
is used to enable running eBPF programs on kernels that don't provide BTF information. A gadget
image can contain at most one btfgen layer. This layer must contain the generated BTF files in a
tarball following the same folder structure of
[btfhub-archive](https://github.com/aquasecurity/btfhub-archive/).

## Image annotations

OCI images can have annotations at different levels:
- index
- manifest
- config
- layer

Inspektor Gadget automatically adds the following annotations at the manifest and config levels:
- `org.opencontainers.image.*`: defined by [OCI Image Format](https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys)
  - title
  - description
  - url
  - documentation
  - source
  - created
