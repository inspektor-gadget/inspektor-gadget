---
title: 'Publishing a gadget'
sidebar_position: 900
description: 'Publishing Inspektor Gadget images to Artifact Hub'
---

Inspektor Gadget gadgets are distributed as OCI images and are expected to be published to a container registry and indexed by [Artifact Hub][artifacthub].
Artifact Hub acts as a central catalog where users can discover and consume
gadgets.

The `ig image build` command produces a gadget image that can be pushed to any
OCI-compatible container registry. Once published, the image can be registered
in Artifact Hub and referenced directly by users.

## Prerequisites

Before publishing a gadget, ensure that:

- The gadget image has been built using `ig image build`
- You have access to an OCI-compatible container registry
- You have an Artifact Hub account with permission to register repositories

This document focuses on Inspektor Gadget–specific steps. Registry setup and Artifact Hub account management are covered in the Artifact Hub documentation.

## Building the gadget image

Gadget images are built using the `ig image build` command. For example:

```bash
$ sudo ig image build . -t ghcr.io/my-org/gadget/mygadget:v0.1.0
````

Ensure the image is correctly built and available locally:

```bash
$ sudo ig image list
```

## Pushing the gadget image

Once built, push the gadget image to your container registry using standard
container tooling:

```bash
$ sudo docker push ghcr.io/my-org/gadget/mygadget:v0.1.0
```

Inspektor Gadget does not require a specific registry, as long as it supports OCI images and is accessible to users.

## Publishing the gadget on Artifact Hub

Artifact Hub indexes content by scanning registered repositories.

To make a gadget discoverable:

1. Register the container registry repository in Artifact Hub
2. Ensure the repository is configured to host OCI artifacts
3. Publish the gadget image to the registered repository

Artifact Hub metadata is extracted from the OCI image and associated repository configuration. Refer to the Artifact Hub documentation for details on required
and optional metadata.

## Verifying the published gadget

After publishing:

* Confirm that the repository appears in Artifact Hub
* Verify that the gadget image and tags are listed
* Check that the gadget metadata is rendered correctly

If the gadget does not appear, ensure the repository is public (or properly
authenticated) and that the image was pushed successfully.

## Running a published gadget

Once published, users can run the gadget by referencing its fully qualified
image name:

```bash
$ sudo ig run ghcr.io/my-org/gadget/mygadget:v0.1.0
```

Artifact Hub provides a canonical reference that can be copied directly.

## Next steps

After publishing a gadget, consider:

* [Signing the gadget image][signing]
* Adding automated tests for the gadget
* Providing usage examples for end users

[artifacthub]: https://artifacthub.io/
[signing]: https://inspektor-gadget.io/docs/latest/gadget-devel/signing

```
