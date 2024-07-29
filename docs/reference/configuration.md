---
title: Configuration
sidebar_position: 400
description: How to configure Inspektor Gadget
---

## Environment Variables

You can use environment variables to configure the behavior of the `run` command. The environment variables use fully qualified names (as in the [configuration file](#configuration-file))
with the prefix `INSPEKTOR_GADGET_`.

```bash
# Enable verbose output
$ export INSPEKTOR_GADGET_VERBOSE=true
$ kubectl gadget run trace_open
DEBU[0000] using target "gadget-b7jrc" ("minikube-docker")
...
# Disable image verification (not recommended)
$ export INSPEKTOR_GADGET_OPERATOR_OCI_VERIFY_IMAGE=false
$ sudo ig run trace_open
WARN[0000] Ignoring runtime "cri-o" with non-existent socketPath "/run/crio/crio.sock"
WARN[0000] image signature verification is disabled due to using corresponding option
WARN[0000] image signature verification is disabled due to using corresponding option
...
```

## Configuration File

You can use a configuration file to set specific settings that persist across multiple executions. The default location for the configuration file is `~/.ig/config.yaml`.
You can change the location of the configuration file specifying the `--config` flag.

The default configuration file can be generated using the following command:

```bash
# Default configuration file for kubectl gadget
$ kubectl gadget config default
as: ""
as-group: []
as-uid: ""
cache-dir: /home/qasim/.kube/cache
...

# Default configuration file for ig
$ ig config default
auto-mount-filesystems: "false"
auto-wsl-workaround: "false"
operator:
    localmanager:
        containerd-namespace: k8s.io
...

# Default configuration file for gadgetctl
$ gadgetctl config default
operator:
    oci:
        authfile: /var/lib/ig/config.json
...
```

You can use the default configuration as a starting point (e.g. `ig config default > ~/.ig/config.yaml`) and modify it to suit your needs.

The current configuration can be printed using the following command:

```bash
# Print the current configuration for kubectl gadget
$ kubectl gadget config view
as: ""
as-group: []
as-uid: ""
cache-dir: /home/qasim/.kube/cache
...

# Print the current configuration for ig
$ ig config view
operator:
    localmanager:
        containerd-namespace: k8s.io
        runtimes: docker,containerd,cri-o,podman
...
# Print the current configuration for gadgetctl
$ gadgetctl config view
operator:
    oci:
        authfile: /var/lib/ig/config.json
        insecure: "false"
...
```

## Precedence

The precedence order of the configuration settings is as follows:
- Flags passed to the command
- Environment variables
- Configuration file
- Default values

(this is due to Inspektor Gadget using the [viper](https://github.com/spf13/viper?tab=readme-ov-file#why-viper) library)
