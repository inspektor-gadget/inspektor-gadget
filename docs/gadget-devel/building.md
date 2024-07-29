---
title: 'Building a Gadget'
sidebar_position: 700
description: 'image build command documentation'
---

The `ig` binary is used to build gadgets. It provides the `image build` command that compiles and packages a gadget in an OCI image.

```bash
$ sudo ig image build -h
Build a gadget image

Usage:
  ig image build PATH [flags]

Flags:
      --btfgen                  Enable btfgen
      --btfhub-archive string   Path to the location of the btfhub-archive files
      --builder-image string    Builder image to use (default "ghcr.io/inspektor-gadget/ebpf-builder:latest")
  -f, --file string             Path to build.yaml (default "build.yaml")
  -h, --help                    help for build
  -l, --local                   Build using local tools
  -o, --output string           Path to a folder to store generated files while building
  -t, --tag string              Name for the built image (format name:tag)
      --update-metadata         Update the metadata according to the eBPF code
      --validate-metadata       Validate the metadata file before building the gadget image (default true)
```

By default, the command looks for a `program.bpf.c` file containing the eBPF source code and for a
`gadget.yaml` with the gadget's metadata in PATH.

```bash
$ ls
gadget.yaml  program.bpf.c

$ sudo ig image build . -t foo:latest
...
Successfully built ghcr.io/inspektor-gadget/gadget/foo:latest@sha256:2e63f54138ff5d6d7ce88b4d7c491402b33fb8e9ad9eb610e3c1e160624c46c7
```

The built image is now present on the system:

```bash
$ sudo ig image list
REPOSITORY                TAG                       DIGEST       CREATED
foo                       latest                    2e63f54138ff about a minute ago
```

## Customizing your build

The building process is controlled by the `build.yaml` file. The following parameters are available:

- `ebpfsource`: eBPF source code file. It defaults to `program.bpf.c`.
- `metadata`: File containing metadata about the gadget. It defaults to `gadget.yaml`.
- `wasm`: Wasm module. It is unset by default. This field supports two kind of files:
    - `*.wasm`: prebuilt Wasm module
    - `*.go`: automatically built with tinygo
- `cflags`: The C flags used to compile the eBPF program. It is unset by default.

By default, the build command looks for `build.yaml` in PATH. It can be changed with the `--file` flag:

```bash
$ ls
another_name_for_gadget.yaml  another_name_for_program.bpf.c  mybuild.yaml

$ cat mybuild.yaml
ebpfsource: another_name_for_program.bpf.c
metadata: another_name_for_gadget.yaml

$ sudo ig image build . --file mybuild.yaml
Successfully built sha256:2f3ccd6254e232e6476f9f015b15f622c44831986f81a82eec17e9c55d98ccaf
```

## Toolchain location

It is possible to build a gadget using a builder container or by using a local toolchain. By default,
a container image provided by Inspektor Gadget with all the tools (compiler, libraries,
header files) needed to compile your gadgets is used. A different container image can be specified with
`--builder-image`. This option requires docker to be available on the system.

`--local` can be used to use the tools installed on the local machine. In this case, you'll need to
have clang, llvm, the gadget headers (see make install-headers) and the [bpf
headers](https://github.com/libbpf/libbpf/blob/56069cda7897afdd0ae2478825845c7a7308c878/src/Makefile#L160)
installed.

In this case it's possible to control some of the tools used by setting some env variables:

```bash
$ sudo CLANG=clang-15 LLVM_STRIP=llvm-strip-15 ig image build . -f mybuild.yaml --local
```

## Reproducible builds

The `build` command supports the
[`SOURCE_DATE_EPOCH`](https://reproducible-builds.org/docs/source-date-epoch/)
env variable:

```bash
# Set SOURCE_DATE_EPOCH to the last modification of the ebpf program source code.
# It can be set to any epoch you want.
$ export SOURCE_DATE_EPOCH="$(date -r program.bpf.c +%s)"

$ sudo ig image build -t foo:latest .
Successfully built ghcr.io/inspektor-gadget/gadget/foo:latest@sha256:373f077d366ef2703535e8e862b60f8a35cc1a9312e9e203534b8fce554f8749

# Building again produces the exact same digest
$ sudo ig image build -t foo:latest .
Successfully built ghcr.io/inspektor-gadget/gadget/foo:latest@sha256:373f077d366ef2703535e8e862b60f8a35cc1a9312e9e203534b8fce554f8749
```

## In-tree gadgets with Wasm

In order to compile the in-tree gadgets (gadgets shipped in the Inspektor gadget
repository) that use Wasm, it's necessary to define the `IG_SOURCE_PATH` env
variable with the absolute path to the root of the Inspektor Gadget source code.
This is needed to use the latest changes to the Wasm API when building the gadget.

```bash
# Path where the inspektor-gadget folder is
$ export IG_SOURCE_PATH=/home/ig/inspektor-gadget

# Build an in-tree gadget that uses Wasm
$ sudo ig image build $IG_SOURCE_PATH/gadgets/trace_open -t trace_open
Pulling builder image ghcr.io/inspektor-gadget/ebpf-builder:latest
latest: Pulling from inspektor-gadget/ebpf-builder
Digest: sha256:5deec444ea81b866f135430f62b2a580374b7bbcfa5961298cb292546395e3b4
Status: Image is up to date for ghcr.io/inspektor-gadget/ebpf-builder:latest
Successfully built ghcr.io/inspektor-gadget/gadget/trace_open:latest@sha256:d3c0fa005cfc16ae1f9184919b517aa784730ed5bbfb54edc50a3befacbe3383
```
