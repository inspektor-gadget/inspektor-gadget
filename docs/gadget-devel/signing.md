---
title: 'Signing a Gadget'
sidebar_position: 720
description: 'Signing a Gadget'
---

It's highly recommended to sign your gadget images for security reasons. Signed
images ensure integrity and authenticity, adding an extra layer of trust. Tools
like [cosign](https://docs.sigstore.dev/cosign/signing/signing_with_containers/)
can be used for this purpose.

If you publish a gadget without signing it, users running it with the default
settings get the following error:

```bash
no signature found for gadget ghcr.io/your-repo/gadget/trace_open:latest
If the gadget is not signed and you are sure you want to skip signature verification, run or deploy Inspektor Gadget with --verify-image=false
```

See [Verifying Gadget Images](../reference/verify-gadgets.mdx) for the ways
users can verify your gadget once it is signed.
