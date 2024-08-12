---
title: Installing on Linux
sidebar_position: 200
description: How to install Inspektor Gadget on Linux
---

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
$ sudo IG_EXPERIMENTAL=true ig run trace_exec
INFO[0000] Experimental features enabled
...

# pass -E if using export and sudo
$ export IG_EXPERIMENTAL=true
$ sudo -E ig run trace_exec
INFO[0000] Experimental features enabled
...
```
