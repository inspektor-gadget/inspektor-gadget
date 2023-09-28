---
title: image
weight: 80
description: >
  Handling gadget's OCI images.
---

> ⚠️ This command is experimental and could change without prior notification. Check the installation guide to enable [experimental features](install.md#experimental-features).

Gadgets in Inspektor Gadget are packaged as OCI images. This document describes the different
commands available to interact with those images and with OCI registries.

If you're looking to run a gadget, check the [run](./gadgets/run.md) command.

## Authentication

The authentication file holds the credentials necessary for communicating with the registry. By
default it is stored at `/var/lib/ig/config.json`. If the default authentication file does not exist
and you haven't specified one using either the `--authfile PATH` parameter for every involved ig
command or the environment variable `REGISTRY_AUTH_FILE`, your docker credentials
(`~/.docker/config.json`) will be used as fallback.

### `--authfile`

Credentials are stored by default in `/var/lib/ig/config.json`, this can be modified by the passing
the `--authfile` flag to the different commands.  If this flag is not passed and the default
authentication file doesn't exist, the logic fallbacks to use the docker credentails.

### `REGISTRY_AUTH_FILE`

It's possible to override the default path of the authentication file by setting the
`REGISTRY_AUTH_FILE` env variable

```bash
$ export REGISTRY_AUTH_FILE=/var/foo
```

## Commands

### `login`

Login to a container registry.

```bash
$ sudo ig login -h
Login to a container registry on a specified server.

Usage:
  ig login [command options] REGISTRY [flags]

Flags:
      --authfile string   path of the authentication file. Use REGISTRY_AUTH_FILE environment variable to override
      --cert-dir string   use certificates at the specified path to access the registry
      --get-login         Return the current login user for the registry
  -h, --help              help for login
  -p, --password string   Password for registry
      --password-stdin    Take the password from stdin
  -u, --username string   Username for registry
  -v, --verbose           Write more detailed information to stdout

```

```bash
$ sudo ig login ghcr.io -u mauriciovasquezbernal
INFO[0000] Experimental features enabled
Password:
Login Succeeded!

$ sudo ig login ghcr.io --get-login
INFO[0000] Experimental features enabled
mauriciovasquezbernal
```

### `logout`

Logout of a container registry.

```bash
$ sudo ig logout -h
INFO[0000] Experimental features enabled
Logout of a container registry on a specified server.

Usage:
  ig logout [command options] REGISTRY [flags]

Flags:
  -a, --all               Remove the cached credentials for all registries in the auth file
      --authfile string   path of the authentication file. Use REGISTRY_AUTH_FILE environment variable to override
  -h, --help              help for logout

```

```bash
$ sudo ig logout ghcr.io
INFO[0000] Experimental features enabled
Removed login credentials for ghcr.io

$ sudo ig login ghcr.io --get-login
INFO[0000] Experimental features enabled
Error: not logged into ghcr.io
```

### `image`

```bash
$ sudo ig image -h
INFO[0000] Experimental features enabled
Manage gadget images

Usage:
  ig image [command]

Available Commands:
  build       Build a gadget image
  list        List gadget images on the host
  pull        Pull the specified image from a remote registry
  push        Push the specified image to a remote registry
  tag         Tag the local SRC_IMAGE image with the DST_IMAGE
```

The following subcommands are available:

#### `build`

The build command compiles and packages a gadget in an OCI image.

```bash
$ sudo ig image build -h
INFO[0000] Experimental features enabled
Build a gadget image

Usage:
  ig image build PATH [flags]

Flags:
      --builder-image string   Builder image to use (default "ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder:latest")
  -f, --file string            Path to build.yaml (default "build.yaml")
  -h, --help                   help for build
  -l, --local                  Build using local tools
  -t, --tag string             Name for the built image (format name:tag)

```

By default, the command looks for a `program.bpf.c` file containing the eBPF source code and for a
`gadget.yaml` with the gadget's metadata in PATH.

```bash
$ ls
gadget.yaml  program.bpf.c

$ sudo ig image build .
INFO[0000] Experimental features enabled
Successfully built sha256:adf9a4c636421d09e038eefa15623176195b0de482b25972e09b8bb3390bd3e
```

##### Customizing your build

The building process is controlled by the `build.yaml` file. The following parameters are available:
- `ebpfsource`: eBPF source code file. It defaults to `program.bpf.c`.
- `metadata`: File containing metadata about the gadget. It defaults to `gadget.yaml`.

By default, the build command looks for `build.yaml` in PATH. It can be changed with the `--file` flag:

```bash
$ ls
another_name_for_gadget.yaml  another_name_for_program.bpf.c  mybuild.yaml

$ cat mybuild.yaml
ebpfsource: another_name_for_program.bpf.c
metadata: another_name_for_gadget.yaml

$ sudo ig image build . -f mybuild.yaml
INFO[0000] Experimental features enabled
Successfully built sha256:2f3ccd6254e232e6476f9f015b15f622c44831986f81a82eec17e9c55d98ccaf
```

##### Toolchain location

It is possible to build a gadget using a builder container or by using a local toolchain. By default,
a container image provided by Inspektor Gadget with all the tools (compiler, libraries,
header files) needed to compiled your gadgets is used. A different container image can be specified with
`--builder-image`. This option requires docker to be available on the system.

`--local` can be used to use the tools installed in the local machine. In this case, you'll need to
have clang, llvm, the gadget headers (see make install-headers) and the [bpf
headers](https://github.com/libbpf/libbpf/blob/56069cda7897afdd0ae2478825845c7a7308c878/src/Makefile#L160)
installed.

In this case it's possible to control some of the tools used by setting some env variables:

```bash
$ sudo CLANG=clang-15 LLVM-STRIP=llvm-strip-15 ig image build . -f mybuild.yaml --local
```

#### `list`

List gadget images on the host.

```bash
$ sudo ig image list -h
INFO[0000] Experimental features enabled
List gadget images on the host

Usage:
  ig image list [flags]

Flags:
  -h, --help       help for list
      --no-trunc   Don't truncate output
```

```bash
$ sudo ig image list
INFO[0000] Experimental features enabled
REPOSITORY                                            TAG                                                   DIGEST
docker.io/library/mygadget                            latest                                                adf9a4c63642
ghcr.io/inspektor-gadget/trace_dns                    latest                                                95f570bdf511
ghcr.io/inspektor-gadget/trace_exec                   latest                                                328dd7a244b8
ghcr.io/inspektor-gadget/trace_open                   latest                                                3a23c1f08a8b
```

#### `pull`

Pull the specified image from a remote registry.

```bash
$ sudo ig image pull -h
INFO[0000] Experimental features enabled
Pull the specified image from a remote registry

Usage:
  ig image pull IMAGE [flags]

Flags:
      --authfile string   Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable (default "/var/lib/ig/config.json")
  -h, --help              help for pull
      --insecure          Allow connections to HTTP only registries
```

```bash
$ sudo ig image pull ghcr.io/mauriciovasquezbernal/trace_open
INFO[0000] Experimental features enabled
Pulling ghcr.io/mauriciovasquezbernal/trace_open:latest...
Successfully pulled ghcr.io/mauriciovasquezbernal/trace_open:latest@sha256:842e69c79177908b6998737b86fc691e8fc0b3e45e2030cafcb362cbfcb1c039
```

#### `push`

Push the specified image to a remote registry.

```bash
$ sudo ig image push -h
INFO[0000] Experimental features enabled
Push the specified image to a remote registry

Usage:
  ig image push IMAGE [flags]

Flags:
      --authfile string   Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable (default "/var/lib/ig/config.json")
  -h, --help              help for push
      --insecure          Allow connections to HTTP only registrie
```

```bash
$ sudo ig image push ghcr.io/mauriciovasquezbernal/trace_open
INFO[0000] Experimental features enabled
Pushing ghcr.io/mauriciovasquezbernal/trace_open:latest...
Successfully pushed ghcr.io/mauriciovasquezbernal/trace_open:latest@sha256:842e69c79177908b6998737b86fc691e8fc0b3e45e2030cafcb362cbfcb1c039
```

#### `tag`

Tag the local SRC_IMAGE image with the DST_IMAGE.

```bash
$ sudo ig image tag -h
INFO[0000] Experimental features enabled
Tag the local SRC_IMAGE image with the DST_IMAGE

Usage:
  ig image tag SRC_IMAGE DST_IMAGE [flags]

Flags:
  -h, --help   help for ta
```

```bash
$ sudo ig image tag mygadget:latest ghcr.io/mauriciovasquezbernal/mygadget:latest
INFO[0000] Experimental features enabled
Successfully tagged with ghcr.io/mauriciovasquezbernal/mygadget:latest@sha256:adf9a4c636421d09e038eefa15623176195b0de482b25972e09b8bb3390bd3e9
```
