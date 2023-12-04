---
title: Installing on Linux
weight: 20
description: >
  How to install Inspektor Gadget on Linux
---

<!-- toc -->
- [Installing `ig`](#installing-ig)
  * [Install a specific release](#install-a-specific-release-1)
  * [Compile from source](#compile-from-source-1)
- [Experimental features](#experimental-features)
<!-- /toc -->

## Installing `ig`

The [`ig`](../ig.md) tool can be built and installed
independently. The result is a single binary (statically linked) that can be
copied to a Kubernetes node or any host to trace its containers.

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

### Compile from source

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
$ sudo IG_EXPERIMENTAL=true ig trace exec
INFO[0000] Experimental features enabled
...

# pass -E if using export and sudo
$ export IG_EXPERIMENTAL=true
$ sudo -E ig trace exec
INFO[0000] Experimental features enabled
...
```

