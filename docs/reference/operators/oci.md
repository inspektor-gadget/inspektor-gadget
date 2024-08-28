---
title: oci
sidebar_position: 0
---

The OCI operator handles Gadgets images. It pulls images from the OCI registries
and invokes the different layer operators according to the
[layers](../../spec/oci.md#image-layers-and-media-types) present on the image.

## Global Parameters

### `verify-image`

Verify image using the provided public key. Check [Verify image-based
gadgets](../verify-assets.mdx#verify-image-based-gadgets) to learn more.

Default: `true`

### `public-keys`

Public keys used to verify the gadgets. Check [Verify image-based
gadgets](../verify-assets.mdx#verify-image-based-gadgets) to learn more.

Default: [Inspektor Gadget public
key](https://github.com/inspektor-gadget/inspektor-gadget/blob/main/pkg/resources/inspektor-gadget.pub).

### `allowed-gadgets`

List of allowed gadgets. If a gadget is not part of it, execution will be
denied. By default, all digests are allowed. Check [Restricting
Gadgets](../restricting-gadgets.mdx) to get more details.

### `insecure-registries`

List of registries to access over plain HTTP. Check [Insecure
Registries](../insecure-registries.mdx) to learn more.

### `disallow-pulling`

Disallow pulling gadgets from registries. Check [Disallow pulling
Gadgets](../disallow-pulling.mdx) to learn more.

Default: `false`

## Instance Parameters

### `authfile`

TODO: is this really a instance param?

Path of the authentication file. This overrides the `REGISTRY_AUTH_FILE`
environment variable.

Fully qualified name: `operators.oci.authfile`

Default: `/var/lib/ig/config.json`

### `validate-metadata`

Validate the gadget metadata before running the gadget

Fully qualified name: `operators.oci.validate-metadata`

Default: `true`

### `pull`

Specify when the gadget image should be pulled
Possible Values:
- `always`: Always pull the gadget image.
- `missing`: Pull the gadget image only if missing.
- `never`: Never pull the gadget image.

Fully qualified name: `operators.oci.pull`

Default: `missing`

### `pull-secret`

Secret to use when pulling the gadget image

Fully qualified name: `operators.oci.pull-secret`
