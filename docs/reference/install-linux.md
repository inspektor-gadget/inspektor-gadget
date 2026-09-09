---
title: Installing on Linux
sidebar_position: 200
description: How to install Inspektor Gadget on Linux
---

To use Inspektor Gadget on a Linux machine, choose one of the following methods:
* [Install a specific release](#install-a-specific-release)
* [Install from distribution package](#install-from-distribution-package)
* [Compilation from source](#compilation-from-source)

### Install a specific release

It is possible to download the asset for a given release and platform from the
[releases page](https://github.com/inspektor-gadget/inspektor-gadget/releases/).

For instance, to download the latest release for linux-amd64:

```bash
$ IG_VERSION=$(curl -s https://api.github.com/repos/inspektor-gadget/inspektor-gadget/releases/latest | jq -r .tag_name)
$ IG_ARCH=amd64
$ curl -sL https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${IG_VERSION}/ig-linux-${IG_ARCH}-${IG_VERSION}.tar.gz | sudo tar -C /usr/local/bin -xzf - ig
$ ig version
```

We strongly advise you to verify `ig` by following our [detailed instructions](./verify-assets.mdx#verify-an-asset).

### Install from distribution package

`ig` is packaged for the following distributions:

[![`ig`](https://repology.org/badge/vertical-allrepos/inspektor-gadget.svg)](https://repology.org/project/inspektor-gadget/versions)

### Compilation from source

`ig` is built using a Docker container relying on [Docker Buildx](https://docs.docker.com/buildx/working-with-buildx), so you don't have to worry
about installing dependencies:

```bash
$ make ig
$ sudo cp ig /usr/local/bin/
```

## Experimental features

Inspektor Gadget has some experimental features disabled by default. Users can enable those
features, however they don't provide any stability and could be removed at any time.

Experimental features can be enabled in `ig` by using the `IG_EXPERIMENTAL` env variable.

```bash
$ sudo IG_EXPERIMENTAL=true ig run trace_exec
INFO[0000] Experimental features enabled
...

# if the variable is already exported, ask sudo to preserve it
$ export IG_EXPERIMENTAL=true
$ sudo --preserve-env=IG_EXPERIMENTAL ig run trace_exec
INFO[0000] Experimental features enabled
...
```

`sudo` resets the environment, so the variable has to be passed on the `sudo`
command line or named in `--preserve-env`. Do not use `sudo -E`: it is silently
ignored by [sudo-rs](https://github.com/trifectatechfoundation/sudo-rs), which
is the default `sudo` implementation since Ubuntu 25.10.
