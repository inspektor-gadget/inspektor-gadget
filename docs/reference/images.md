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
Password:
Login Succeeded!

$ sudo ig login ghcr.io --get-login
mauriciovasquezbernal
```

### `logout`

Logout of a container registry.

```bash
$ sudo ig logout -h
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
Removed login credentials for ghcr.io

$ sudo ig login ghcr.io --get-login
Error: not logged into ghcr.io
```

### `image`

```bash
$ sudo ig image -h
Manage gadget images

Usage:
  ig image [command]

Available Commands:
  build       Build a gadget image
  export      Export the SRC_IMAGE images to DST_FILE
  import      Import images from SRC_FILE
  inspect     Inspect a gadget image
  list        List gadget images on the host
  pull        Pull the specified image from a remote registry
  push        Push the specified image to a remote registry
  remove      Remove local gadget image
  tag         Tag the local SRC_IMAGE image with the DST_IMAGE
```

The following subcommands are available:

#### `build`

See [building](../gadget-devel/building.md) for more information.

#### `list`

List gadget images on the host.

```bash
$ sudo ig image list -h
List gadget images on the host

Usage:
  ig image list [flags]

Flags:
  -h, --help       help for list
      --no-trunc   Don't truncate output
```

```bash
$ sudo ig image list
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
Remove local gadget image

Usage:
  ig image remove IMAGE [flags]

Flags:
  -h, --help   help for remove

```

```bash
$ sudo ig image remove gadget
Successfully removed gadget
```

#### `pull`

Pull the specified image from a remote registry.

```bash
$ sudo ig image pull -h
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
Pulling ghcr.io/mauriciovasquezbernal/trace_open:latest...
Successfully pulled ghcr.io/mauriciovasquezbernal/trace_open:latest@sha256:842e69c79177908b6998737b86fc691e8fc0b3e45e2030cafcb362cbfcb1c039
```

#### `push`

Push the specified image to a remote registry.

```bash
$ sudo ig image push -h
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
Pushing ghcr.io/mauriciovasquezbernal/trace_open:latest...
Successfully pushed ghcr.io/mauriciovasquezbernal/trace_open:latest@sha256:842e69c79177908b6998737b86fc691e8fc0b3e45e2030cafcb362cbfcb1c039
```

#### `tag`

Tag the local SRC_IMAGE image with the DST_IMAGE.

```bash
$ sudo ig image tag -h
Tag the local SRC_IMAGE image with the DST_IMAGE

Usage:
  ig image tag SRC_IMAGE DST_IMAGE [flags]

Flags:
  -h, --help   help for tag
```

```bash
$ sudo ig image tag mygadget:latest ghcr.io/mauriciovasquezbernal/mygadget:latest
Successfully tagged with ghcr.io/mauriciovasquezbernal/mygadget:latest@sha256:adf9a4c636421d09e038eefa15623176195b0de482b25972e09b8bb3390bd3e9
```

#### `export`

Export the SRC_IMAGE images to DST_FILE.

```bash
$ sudo ig image export -h
Export the SRC_IMAGE images to DST_FILE

Usage:
  ig image export SRC_IMAGE [SRC_IMAGE n] DST_FILE [flags]

Flags:
  -h, --help   help for export
```

```bash
# Pull an image
$ sudo ig image pull ghcr.io/inspektor-gadget/gadget/trace_open
Successfully pulled ghcr.io/inspektor-gadget/gadget/trace_open:latest@sha256:19ea8377298f...

# Export it to a file
$ sudo ig image export ghcr.io/inspektor-gadget/gadget/trace_open trace_open.tar
Successfully exported images to trace_open.tar

$ ls -lnh trace_open.tar
-rw-r--r-- 1 0 0 181K abr 24 17:35 trace_open.tar
```

#### `import`

```bash
$ sudo ig image import -h
Import images from SRC_FILE

Usage:
  ig image import SRC_FILE [flags]

Flags:
  -h, --help   help for import
```

```bash
# Remove image if existing
$ sudo ig image remove trace_open
Successfully removed trace_open

$ sudo ig image list
REPOSITORY                     TAG                           DIGEST       CREATED

# Import image exported above
$ sudo ig image import trace_open.tar
Successfully imported images:
  ghcr.io/inspektor-gadget/gadget/trace_open:latest

$ sudo ig image list
REPOSITORY                     TAG                           DIGEST       CREATED
trace_open                     latest                        19ea8377298f 30 minutes ago
```

#### `inspect`

Inspect the given gadget image.

```bash
$ sudo ig image inspect -h
Inspect a gadget image

Usage:
  ig image inspect IMAGE [flags]

Flags:
  -h, --help                  help for inspect
  -o, --output       string   Output mode: json, jsonpretty, yaml (default "jsonpretty")
  --extra-info       string   specify particular info required
  --jsonpath         string   JSONPath to extract from the extra info
  --show-datasources bool     show datasources along with their fields
  ```

```bash
# Pull an image to inspect
$ sudo ig image pull ghcr.io/inspektor-gadget/gadget/trace_tcp
Successfully pulled ghcr.io/inspektor-gadget/gadget/trace_tcp:latest@sha256:a9e26ab904c32b47aec2588cabe11a1839332ee53faef861eac3c5323412395d

# Inspect the image with default output (jsonpretty)
$ sudo ig image inspect ghcr.io/inspektor-gadget/gadget/trace_tcp
{
  "ebpf.maps": {
    "content": "[{\"Name\":\"gadget_heap\",\"Type\":\"PerCPUArray\"},{\"Name\":\"gadget_mntns_filter_map\",\"Type\":\"Hash\"},{\"Name\":\"tuplepid\",\"Type\":\"Hash\"},{\"Name\":\"sockets\",\"Type\":\"Hash\"},{\"Name\":\"events\",\"Type\":\"RingBuf\"}]",
    "contentType": "application/json"
  },
  "ebpf.sections": {
    "content": "[\"\",\".strtab\",\".text\",\"kprobe/tcp_v4_connect\",\".relkprobe/tcp_v4_connect\",\"kretprobe/tcp_v4_connect\",\".relkretprobe/tcp_v4_connect\",\"kprobe/tcp_v6_connect\",\".relkprobe/tcp_v6_connect\",\"kretprobe/tcp_v6_connect\",\".relkretprobe/tcp_v6_connect\",\"kprobe/tcp_close\",\".relkprobe/tcp_close\",\"kprobe/tcp_set_state\",\".relkprobe/tcp_set_state\",\"kretprobe/inet_csk_accept\",\".relkretprobe/inet_csk_accept\",\".rodata\",\".bss\",\"license\",\".maps\",\".BTF\",\".rel.BTF\",\".BTF.ext\",\".rel.BTF.ext\",\".llvm_addrsig\",\".symtab\"]",
    "contentType": "application/json"
  },
  ...
}

# List possible extra-info
$ sudo ig image inspect fsnotify:main |jq keys
[
  "ebpf.flowchart",
  "ebpf.maps",
  "ebpf.programs",
  "ebpf.sections",
  "ebpf.sequence",
  "ebpf.variables",
  "oci.created",
  "oci.digest",
  "oci.manifest",
  "oci.metadata",
  "oci.repository",
  "oci.tag",
  "wasm.gadgetAPIVersion",
  "wasm.upcalls"
]

# Retrieve specific info using --extra-info
$ sudo ig image inspect --extra-info=ebpf.sections ghcr.io/inspektor-gadget/gadget/trace_tcp -o json
["",".strtab",".text","kprobe/tcp_v4_connect",".relkprobe/tcp_v4_connect","kretprobe/tcp_v4_connect",".relkretprobe/tcp_v4_connect","kprobe/tcp_v6_connect",".relkprobe/tcp_v6_connect","kretprobe/tcp_v6_connect",".relkretprobe/tcp_v6_connect","kprobe/tcp_close",".relkprobe/tcp_close","kprobe/tcp_set_state",".relkprobe/tcp_set_state","kretprobe/inet_csk_accept",".relkretprobe/inet_csk_accept",".rodata",".bss","license",".maps",".BTF",".rel.BTF",".BTF.ext",".rel.BTF.ext",".llvm_addrsig",".symtab"]

# Listing programs
$ sudo ig image inspect fsnotify --extra-info ebpf.programs --jsonpath='[*].Section'
[
  "kprobe/fsnotify_insert_event",
  "kretprobe/inotify_handle_inode_event",
  "kretprobe/fanotify_handle_event",
  "kretprobe/fsnotify_remove_first_event",
  "kretprobe/inotify_handle_event",
  "kprobe/fanotify_handle_event",
  "kprobe/fsnotify_destroy_event",
  "kprobe/fsnotify_remove_first_event",
  "kprobe/inotify_handle_inode_event",
  "kprobe/inotify_handle_event"
]

# Printing the source of a program
$ sudo ig image inspect fsnotify:latest --extra-info ebpf.programs|jq -r '.[] | select(.Section=="kprobe/fsnotify_remove_first_event") | .Source'
ig_fa_pick_e:
	  ; int BPF_KPROBE(ig_fa_pick_e, struct fsnotify_group *group)
	 0: LdXMemDW dst: r6 src: r1 off: 112 imm: 0
	 1: StXMemDW dst: rfp src: r6 off: -8 imm: 0
	  ; pid_tgid = bpf_get_current_pid_tgid();
	 2: Call FnGetCurrentPidTgid
...
	25: MovImm dst: r0 imm: 0
	26: Exit

# Printing the gadget annotations
$ sudo ig image inspect audit_seccomp:main --extra-info=oci.manifest --jsonpath='.annotations'
{
  "io.inspektor-gadget.builder.version": "fb7bfcd",
  "org.opencontainers.image.created": "2025-04-10T08:49:17Z",
  "org.opencontainers.image.description": "Audit syscalls according to the seccomp profile",
  "org.opencontainers.image.documentation": "https://www.inspektor-gadget.io/docs/latest/gadgets/audit_seccomp",
  "org.opencontainers.image.source": "https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets/audit_seccomp",
  "org.opencontainers.image.title": "audit seccomp",
  "org.opencontainers.image.url": "https://inspektor-gadget.io/"
}

# Indexing ebpf programs using the jsonpath flag
$ sudo ig image inspect advise_seccomp:latest --extra-info=ebpf.programs --jsonpath="[0].Section"
"raw_tracepoint/sys_enter"

# Indexing oci manifest fields using jsonpath flag
$ sudo ig image inspect advise_seccomp:latest --extra-info=oci.manifest --jsonpath=".layers[0].digest"
"sha256:36f802754b93c6592a9d44e6a6b5ee4910773750966f230f3f10324065017639"

# Printing the gadget metadata
$ sudo ig image inspect audit_seccomp:main --extra-info=oci.metadata
name: audit seccomp
description: Audit syscalls according to the seccomp profile
homepageURL: https://inspektor-gadget.io/
documentationURL: https://www.inspektor-gadget.io/docs/latest/gadgets/audit_seccomp
sourceURL: https://github.com/inspektor-gadget/inspektor-gadget/tree/main/gadgets/audit_seccomp
datasources:
  seccomp:
    fields:
      syscall_raw:
        annotations:
          columns.hidden: true
      syscall:
        annotations:
          columns.width: 20
      code:
        annotations:
          description: Seccomp return code
          columns.width: 20
          columns.ellipsis: start
      ustack:
        annotations:
          columns.hidden: true
      ustack.addresses:
        annotations:
          description: User stack's addresses
          columns.hidden: true
          columns.width: 20
      ustack.symbols:
        annotations:
          description: User stack's symbols
          columns.hidden: true
          columns.width: 20
params:
  ebpf:
    collect_ustack:
      key: collect-ustack
      defaultValue: "false"
      description: Collect user stack traces

# Listing the layers from the oci manifest
$ sudo ig image inspect advise_seccomp:latest --extra-info=oci.manifest --jsonpath=".layers[*].mediaType" -o yaml
- application/vnd.gadget.ebpf.program.v1+binary
- application/vnd.gadget.wasm.program.v1+binary

# List the fields of a datasource
$ sudo ig image inspect advise_seccomp:latest --show-datasources --jsonpath='[0].fields[*].fullName'
[
  "mntns_id_raw",
  "syscalls",
  "k8s",
  "k8s.node",
  "k8s.namespace",
  "k8s.podName",
  "k8s.containerName",
  "k8s.hostnetwork",
  "k8s.podLabels",
  "k8s.owner",
  "k8s.owner.kind",
  "k8s.owner.name",
  "runtime",
  "runtime.containerName",
  "runtime.runtimeName",
  "runtime.containerId",
  "runtime.containerPid",
  "runtime.containerImageName",
  "runtime.containerImageDigest",
  "runtime.containerStartedAt"
]
```

#### `verify`

Verify the given gadget image signature.

```bash
$ sudo ig image verify -h
PASTE_HERE_THE_OUTPUT_OF_THE_COMMAND

Verify gadget signatures

Usage:
  ig image verify [gadget] [flags]

Flags:
  -h, --help                              help for verify
      --notation-certificates strings     Certificates for Notation verification
      --notation-policy-document string   Trust policy JSON for Notation verification
      --public-keys strings               Inline Cosign public key (use --public-keys="$(cat your-key.pub)") (default ["-----BEGIN PUBLIC KEY-----
                                          MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEoDOC0gYSxZTopenGmX3ZFvQ1DSfh
                                          Ir4EKRt5jC+mXaJ7c7J+oREskYMn/SfZdRHNSOjLTZUMDm60zpXGhkFecg==
                                          -----END PUBLIC KEY-----
                                          "])

Global Flags:
      --auto-mount-filesystems   Automatically mount bpffs, debugfs and tracefs if they are not already mounted
      --auto-wsl-workaround      Automatically find the host procfs when running in WSL2
      --config string            config file to use
      --pprof-addr string        Starts a pprof server for profiling at the given address (e.g., 'localhost:6060'), leave empty to disable (default).
  -v, --verbose                  Print debug information

  ```bash
$ sudo ig image verify --public-keys="\"$(cat cosign.pub)\"" ghcr.io/inspektor-gadget/gadget/trace_exec:v0.45.0
 
Verifying image: ghcr.io/inspektor-gadget/gadget/trace_exec:v0.45.0
Image verified successfully!