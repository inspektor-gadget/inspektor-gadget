---
title: image
weight: 80
description: >
  Handling gadget's OCI images.
---

Gadgets in Inspektor Gadget are packaged as OCI images. This document describes the different
commands available to interact with those images and with OCI registries.

### Authentication

Users can login and logout from a registry by using the following two commands.

### `login`

Login to a container registry

### `logout`

Logout of a container registry

### --authfile

Credentials are stored by default in `/var/lib/ig/config.json`, this can be modified by the passing
the `--authfile` flag to the different commands.  If this flag is not passed and the default
authentication file doesn't exist, the logic fallbacks to use the docker credentails.

## `image`

The following subcommands are available:

### `build`

Build a gadget image

### `list`

List gadget images in the host

### `pull`

Pull the specified image from a remote registry

### `push`

Push the specified image to a remote registry

### `tag`

Tag the local SRC_IMAGE image with the DST_IMAGE
