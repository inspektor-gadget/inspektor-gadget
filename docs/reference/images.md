---
title: Handling Gadgets
sidebar_position: 500
description: Handling Gadget Images
---

Gadgets in Inspektor Gadget are packaged as OCI artifacts. This document
describes the different commands available to interact with those artifacts and
with OCI registries. If you're looking to run a gadget, check the [run](run.mdx)
command.

## Authentication

The authentication file holds the credentials necessary for communicating with the registry. By
default it is stored at `/var/lib/ig/config.json`. If the default authentication file does not exist
and you haven't specified one using either the `--authfile PATH` parameter for every involved ig
command or the environment variable `REGISTRY_AUTH_FILE`, your docker credentials
(`~/.docker/config.json`) will be used as fallback.

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

See [building](../gadget-devel/building.md) for more information.

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

#### `remove`

Remove the given gadget image from the host.

```bash
$ sudo ig image remove -h
INFO[0000] Experimental features enabled
Remove local gadget image

Usage:
  ig image remove IMAGE [flags]

Flags:
  -h, --help   help for remove

```

```bash
$ sudo ig image remove gadget
INFO[0000] Experimental features enabled
Successfully removed gadget
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
      --authfile string               Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable (default "/var/lib/ig/config.json")
  -h, --help                          help for pull
      --insecure-registries strings   List of registries to access over plain HTTP
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
      --authfile string               Path of the authentication file. This overrides the REGISTRY_AUTH_FILE environment variable (default "/var/lib/ig/config.json")
  -h, --help                          help for push
      --insecure-registries strings   List of registries to access over plain HTTP
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
  -h, --help   help for tag
```

```bash
$ sudo ig image tag mygadget:latest ghcr.io/mauriciovasquezbernal/mygadget:latest
INFO[0000] Experimental features enabled
Successfully tagged with ghcr.io/mauriciovasquezbernal/mygadget:latest@sha256:adf9a4c636421d09e038eefa15623176195b0de482b25972e09b8bb3390bd3e9
```

#### `export`

Export the SRC_IMAGE images to DST_FILE.

```bash
$ sudo ig image export -h
INFO[0000] Experimental features enabled
Export the SRC_IMAGE images to DST_FILE (experimental)

Usage:
  ig image export SRC_IMAGE [SRC_IMAGE n] DST_FILE [flags]

Flags:
  -h, --help   help for export
```

```bash
# Pull an image
$ sudo -E ig image pull ghcr.io/inspektor-gadget/gadget/trace_open
INFO[0000] Experimental features enabled

# Export it to a file
$ sudo -E ig image export ghcr.io/inspektor-gadget/gadget/trace_open trace_open.tar
INFO[0000] Experimental features enabled
Successfully exported images to trace_open.tar

$ ls -lnh trace_open.tar
-rw-r--r-- 1 0 0 181K abr 24 17:35 trace_open.tar
```

#### `import`

```bash
$ sudo -E ig image import -h
INFO[0000] Experimental features enabled
Import images from SRC_FILE (experimental)

Usage:
  ig image import SRC_FILE [flags]

Flags:
  -h, --help   help for import
```

```bash
# Remove image if existing
$ sudo -E ig image remove trace_open
INFO[0000] Experimental features enabled
Successfully removed trace_open

$ sudo -E ig image list
INFO[0000] Experimental features enabled
REPOSITORY                     TAG                           DIGEST       CREATED

# Import image exported above
$ sudo -E ig image import trace_open.tar
INFO[0000] Experimental features enabled
Successfully imported images:
  ghcr.io/inspektor-gadget/gadget/trace_open:latest

$ sudo -E ig image list
INFO[0000] Experimental features enabled
REPOSITORY                     TAG                           DIGEST       CREATED
trace_open                     latest                        19ea8377298f 30 minutes ago
```
