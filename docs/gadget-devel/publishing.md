---
title: 'Publishing your gadget'
sidebar_position: 900
description: 'Publishing Inspektor Gadget images to an OCI registry and optionally to Artifact Hub'
---

Inspektor Gadget gadgets are distributed as OCI images. To make a gadget usable,
it must be pushed to an OCI-compatible container registry. Optionally, gadgets
can be indexed in [Artifact Hub][artifacthub] to make them easier to discover and
consume by others.

This document covers:
- Publishing a gadget image to an OCI registry (required)
- Publishing a gadget to Artifact Hub for discoverability (optional)

## Prerequisites

Before publishing a gadget, ensure that:

- The gadget image has been built using `ig image build`
- You have access to an OCI-compatible container registry

Publishing to Artifact Hub additionally requires an Artifact Hub account with
permission to register repositories.

For details on building gadget images, see the
[Building a Gadget documentation][building].

## Publishing a gadget to an OCI registry

Once the gadget image has been built, push it to your container registry using
the `ig image push` command:

```bash
$ sudo ig image push ghcr.io/my-org/gadget/mygadget:v0.1.0
````

After this step, the gadget can be run directly by referencing its fully
qualified image name:

```bash
$ sudo ig run ghcr.io/my-org/gadget/mygadget:v0.1.0
```

An OCI registry is sufficient for distributing and running gadgets. No
additional services are required.

## (Optional) Publishing the gadget on Artifact Hub

Artifact Hub provides a central catalog where users can discover available
gadgets, view metadata, and copy canonical references.

Publishing a gadget to Artifact Hub is optional but recommended if you want to:

* Make the gadget discoverable by a wider audience
* Provide searchable metadata and documentation
* Offer a stable reference for users

To publish a gadget on Artifact Hub:

1. Register your container registry repository in Artifact Hub
2. Ensure the repository is configured to host OCI artifacts
3. Push the gadget image to the registered repository

Artifact Hub indexes gadget images by scanning registered repositories. Metadata
is extracted from the OCI image and repository configuration. Refer to the
Artifact Hub documentation for details on required and optional metadata.

## Verifying publication on Artifact Hub

After publishing to Artifact Hub:

* Confirm that the repository appears in Artifact Hub
* Verify that the gadget image and tags are listed
* Check that the gadget metadata is rendered correctly

If the gadget does not appear, ensure the repository is public (or properly
authenticated) and that the image was pushed successfully.

## Next steps

After publishing a gadget, consider:

* [Signing the gadget image][signing]
* Providing usage examples for end users

[artifacthub]: https://artifacthub.io/
[building]: ./building.md
[signing]: ./signing.md


