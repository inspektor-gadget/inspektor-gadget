---
title: Verifying
weight: 120
description: >
  Verify Inspektor Gadget
---

Inspektor Gadget container image and release assets are signed using
[`cosign`](https://github.com/sigstore/cosign).
In this guide, we will see how you can verify them with this tool.
Note that, You would need to have `cosign` [v2.0](https://github.com/sigstore/cosign/blob/main/README.md#developer-installation) installed.

## Verify the container image manually

Verifying the container image is pretty straightforward:

```bash
$ RELEASE='v0.23.0'
$ URL="https://github.com/inspektor-gadget/inspektor-gadget/blob/main/inspektor-gadget.pub"
# We first need to get the public key.
$ wget $URL
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/inspektor-gadget:${RELEASE}
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/inspektor-gadget"}, ...
]
```

Getting the above output followed by a JSON array of payloads, ensures you the
container image was signed using our private key.

## Verify the container image while deploying

You can also verify the container image at runtime by using `policy-controller`.
To do so, you first need to [install](https://docs.sigstore.dev/policy-controller/installation/) this component on your kubernetes cluster.
We will then deploy an `admission-controller` using the following YAML file:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata:
  name: image-policy
spec:
  images:
  - glob: "ghcr.io/inspektor-gadget/inspektor-gadget**"
  authorities:
    - key:
        hashAlgorithm: sha256
        data: |
          # content of inspektor-gadget.pub
```

This `admission-controller` will only accept the image if it was signed with the given public key.
By default, this `admission-controller` does nothing, we need to activate it on namespaces of interests:

```bash
$ kubectl apply -f admission.yaml
clusterimagepolicy.policy.sigstore.dev/image-policy created
$ kubectl create ns gadget
namespace/gadget created
$ kubectl label namespace gadget policy.sigstore.dev/include=true
namespace/gadget labeled
```

The `admission-controller` is now activated on the `gadget` namespace, let's try to deploy Inspektor Gadget:

```bash
$ kubectl-gadget deploy
...
1/1 gadget pod(s) ready
...
Inspektor Gadget successfully deployed
```

As you can see, everything was successfully deployed.
Now, let's undeploy Inspektor Gadget and try to deploy an old release which was not signed:

```bash
$ kubectl gadget undeploy
...
Inspektor Gadget successfully removed
$ kubectl create ns gadget
namespace/gadget created
$ kubectl label namespace gadget policy.sigstore.dev/include=true
namespace/gadget labeled
$ kubectl gadget deploy --image 'ghcr.io/inspektor-gadget/inspektor-gadget:v0.22.0'
...
Creating DaemonSet/gadget...
Error: problem while creating resource: creating "DaemonSet": admission webhook "policy.sigstore.dev" denied the request: validation failed: failed policy: image-policy: spec.template.spec.containers[0].image
ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f signature key validation failed for authority authority-0 for ghcr.io/inspektor-gadget/inspektor-gadget@sha256:9272c2be979a9857971fc8b6f7226e609cadec8352f97e9769081930121ef27f: no matching signatures
```

As this image is not signed, the verification failed and the container was not deployed to the cluster.

## Verify the container Source Code Bill Of Materials (SBOMs)

A Software Bill of Materials (SBOM) is a detailed list of all the components of a software.
It facilitates security and license compliance assessments.
The Inspektor Gadget project publishes SBOMs in the [CycloneDX format](https://cyclonedx.org/specification/overview/) for all our container images and CLI tools:
* SBOMs for container images are attached to the corresponding image and can be found in our [registry](https://github.com/orgs/inspektor-gadget/packages).
* SBOMs for CLI tools are available as [release](https://github.com/inspektor-gadget/inspektor-gadget/releases) assets.

In this section, we will see how you can verify and inspect the SBOMs attached to our container images.
To do so, you will need `cosign`, [`oras`](https://oras.land/docs/installation) and Inspektor Gadget public key.

```bash
# We will demo this for amd64, but it works the same for arm64.
$ arch=amd64
$ oras discover --platform linux/${arch} --artifact-type example/sbom ghcr.io/inspektor-gadget/inspektor-gadget:latest
Discovered 1 artifact referencing latest
Digest: sha256:...

Artifact Type   Digest
example/sbom    sha256:hash_of_sbom_manifest
# As we include SBOMs in our multi architecture container image, they are also
# signed.
# So, let's check the SBOM is signed with our private key:
$ cosign verify --key inspektor-gadget.pub ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest

Verification for ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The signatures were verified against the specified public key

[{"critical":{"identity":{"docker-reference":"ghcr.io/inspektor-gadget/inspektor-gadget"}, ...
]
# Let's download the SBOM and look at it:
$ oras pull --allow-path-traversal ghcr.io/inspektor-gadget/inspektor-gadget@sha256:hash_of_sbom_manifest
Downloading 1d479bb51392 /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
Downloaded  1d479bb51392 /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
Pulled [registry] ghcr.io/eiffel-fl/inspektor-gadget@sha256:hash_of_sbom_manifest
Digest: sha256:hash_of_sbom_manifest
$ jq '' /tmp/gadget-container-image-linux-amd64/sbom_cyclonedx.json
{
  "$schema": "http://cyclonedx.org/schema/bom-1.5.schema.json",
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "serialNumber": "urn:uuid:cf132c3d-5960-4536-9c03-9724babd76e9",
  "version": 1,
  "metadata": {
    "timestamp": "2024-03-21T17:22:38Z",
    "tools": {
      "components": [
        {
          "type": "application",
          "author": "anchore",
          "name": "syft",
          "version": "1.0.1"
        }
      ]
    },
    "component": {
      "bom-ref": "af63bd4c8601b7f1",
      "type": "file",
      "name": "."
    }
  },
  "components": [
    {
      "bom-ref": "pkg:deb/debian/base-files@12.4+deb12u5?arch=amd64&distro=debian-12&package-id=854ccee33785ad46",
      "type": "library",
      "publisher": "Santiago Vila <sanvila@debian.org>",
      "name": "base-files",
...
```

As the SBOM was signed with our private key, you can now inspect it to track down every dependencies we use to build our container image.

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
