---
title: Verifying
weight: 100
description: >
  Verify Inspektor Gadget
---

Inspektor Gadget container image and release assets are signed using
[`cosign`](https://github.com/sigstore/cosign).
In this guide, we will see how you can verify them with this tool.
Note that, You would need to have `cosign` [v2.0](https://github.com/sigstore/cosign/blob/main/README.md#developer-installation) installed.

## Verify the container image

Verifying the container image is pretty straightforward:

```bash
$ RELEASE='v0.23.0'
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
# We first need to get the public key.
$ wget $URL/inspektor-gadget.pub
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/inspektor-gadget:${RELEASE}
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/inspektor-gadget"}, ...
]
```

Getting the above output followed by a JSON array of payloads, ensures you the
container image was sign using our private key.

## Verify an asset

Rather than signing all the assets, we only sign the checksums file.
So, by verifying this file, you can then verify the assets themselves by
checking their checksums.

## Verifying the checksums file

The following snippet show you how to verify the checksums file:

```bash
$ RELEASE='v0.19.0'
$ ASSET="SHA256SUMS"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
# We need to get the asset itself, its signature file and the corresponding bundle:
$ for i in $URL/$ASSET $URL/$ASSET.sig $URL/$ASSET.bundle; do
	wget $i
done
...
# We need to get the public key too.
$ wget $URL/inspektor-gadget.pub
...
$ cosign verify-blob $ASSET --bundle ${ASSET}.bundle --signature ${ASSET}.sig --key inspektor-gadget.pub --offline
Verified OK
```

As you can see, the checksum file was correctly verified which means this file was indeed signed by us.
So, you can use this file to verify other release assets.

## Verify an asset

Once you verified the checksums file, you can now verify the integrity of an asset using such checksums file:

```bash
$ RELEASE='v0.19.0'
$ ASSET="inspektor-gadget-${RELEASE}.yaml"
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/releases/download/${RELEASE}"
$ wget $URL/$ASSET
$ grep $ASSET SHA256SUMS | shasum -a 256 -c -s || echo "Error: ${ASSET} didn't pass the checksum verification. You must not use it!"
```
