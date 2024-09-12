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

## ArtifactType

Media type: `application/vnd.gadget.v1+binary`

This indicates the manifest is a Gadget. It follows the guidelines in:
https://github.com/opencontainers/image-spec/blob/main/manifest.md#guidelines-for-artifact-usage.

## Gadget metadata

Media type: `application/vnd.gadget.config.v1+yaml`

This contains the [gadget metadata](../gadget-devel/metadata.md).

## Image layers and media types

Each architecture can contain several layers, but each layer must have a
different media type among the following:

- `application/vnd.gadget.ebpf.program.v1+binary`
- `application/vnd.gadget.wasm.program.v1+binary`
- `application/vnd.gadget.btfgen.v1+binary`

### The ebpf layer

There must be exactly one layer with the ebpf media type. It must not be empty.
Its content must be a valid ELF file. See [gadget eBPF
API](../gadget-devel/gadget-ebpf-api.md).

### The wasm layer

There must be at most one layer with the wasm media type. If present, it must
not be empty and it must be a valid wasm file. See [WASM
API](../gadget-devel/gadget-wasm-api-raw.md).

### The btfgen layer

[btfgen](https://www.inspektor-gadget.io/blog/2022/03/btfgen-one-step-closer-to-truly-portable-ebpf-programs/)
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
