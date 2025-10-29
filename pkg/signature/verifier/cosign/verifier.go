// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cosign

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	sigstorebundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry"
	"oras.land/oras-go/v2/registry/remote"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

type VerifierOptions struct {
	PublicKeys []string
}

type Verifier struct {
	verifiers []signature.Verifier
}

const (
	// Taken from:
	// https://github.com/sigstore/cosign/blob/45bda40b8ef4/internal/pkg/oci/remote/remote.go#L24
	signatureArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"

	// Taken from:
	// https://github.com/sigstore/cosign/blob/ee3d9fe1c55e/pkg/cosign/bundle/protobundle.go#L36
	bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

	// Taken from:
	// https://github.com/sigstore/cosign/blob/45bda40b8ef4/pkg/types/media.go#L28
	simpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
)

const (
	legacyFormat  string = "legacy"
	oci11Format   string = "oci 1.1"
	bundleFormat  string = "bundle"
)

var supportedFormats = []string{legacyFormat, oci11Format, bundleFormat}

func pullCosignSigningInformation(ctx context.Context, repo *remote.Repository, signingInfoTag string, imageStore oras.Target) error {
	if _, err := oras.Copy(ctx, repo, signingInfoTag, imageStore, signingInfoTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copying index tag %q: %w", signingInfoTag, err)
	}

	return nil
}

func loadSignatureAndPayloadNotBundle(ctx context.Context, imageStore oras.Target, signatureTag string) ([]byte, []byte, error) {
	_, signatureManifestBytes, err := oras.FetchBytes(ctx, imageStore, signatureTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("getting signature bytes: %w", err)
	}

	signatureManifest := &ocispec.Manifest{}
	err = json.Unmarshal(signatureManifestBytes, signatureManifest)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding signature manifest: %w", err)
	}

	layers := signatureManifest.Layers
	expectedLen := 1
	layersLen := len(layers)
	if layersLen != expectedLen {
		return nil, nil, fmt.Errorf("wrong number of signature manifest layers: expected %d, got %d", expectedLen, layersLen)
	}

	payloadDescriptor := layers[0]
	if payloadDescriptor.MediaType != simpleSigningMediaType {
		return nil, nil, fmt.Errorf("wrong payloadDescriptor media type: expected %s, got %s", simpleSigningMediaType, payloadDescriptor.MediaType)
	}

	signature, ok := payloadDescriptor.Annotations["dev.cosignproject.cosign/signature"]
	if !ok {
		return nil, nil, fmt.Errorf("no signature in payloadDescriptor")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding signature: %w", err)
	}

	payloadBytes, err := content.FetchAll(ctx, imageStore, payloadDescriptor)
	if err != nil {
		return nil, nil, fmt.Errorf("getting payload bytes: %w", err)
	}

	return signatureBytes, payloadBytes, nil
}

func loadSignatureAndPayloadForBundle(ctx context.Context, imageStore oras.Target, signatureTag string) ([]byte, []byte, error) {
	_, bundleBytes, err := oras.FetchBytes(ctx, imageStore, signatureTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, nil, fmt.Errorf("getting bundle bytes: %w", err)
	}

	bundle := &sigstorebundle.Bundle{}
	err = protojson.Unmarshal(bundleBytes, bundle)
	if err != nil {
		return nil, nil, fmt.Errorf("decoding bundle: %w", err)
	}

	envelope := bundle.GetDsseEnvelope()
	if envelope == nil {
		return nil, nil, errors.New("DSSE envelope not found in bundle")
	}

	signatures := envelope.GetSignatures()
	expectedLen := 1
	signaturesLen := len(signatures)
	if signaturesLen != expectedLen {
		return nil, nil, fmt.Errorf("wrong number of signatures: expected %d, got %d", expectedLen, signaturesLen)
	}

	return signatures[0].Sig, dsse.PAE(envelope.GetPayloadType(), envelope.GetPayload()), nil
}

func loadSignatureAndPayload(ctx context.Context, imageStore oras.Target, signatureTag string, format string) ([]byte, []byte, error) {
	switch format {
	case legacyFormat, oci11Format:
		return loadSignatureAndPayloadNotBundle(ctx, imageStore, signatureTag)
	case bundleFormat:
		return loadSignatureAndPayloadForBundle(ctx, imageStore, signatureTag)
	default:
		return nil, nil, fmt.Errorf("signature format %q unknown, expected one in %v", format, strings.Join(supportedFormats, ","))
	}
}

func getSignatureTagOci11(ctx context.Context, imageStore oras.Target, signingInfoTag string) (string, error) {
	_, indexBytes, err := oras.FetchBytes(ctx, imageStore, signingInfoTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return "", fmt.Errorf("getting index bytes: %w", err)
	}

	index := &ocispec.Index{}
	err = json.Unmarshal(indexBytes, index)
	if err != nil {
		return "", fmt.Errorf("decoding index: %w", err)
	}

	for _, manifest := range index.Manifests {
		if manifest.ArtifactType == signatureArtifactType {
			return manifest.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("signature tag not found for index %q", signingInfoTag)
}

func getSignatureTagBundle(ctx context.Context, imageStore oras.Target, signingInfoTag string) (string, error) {
	_, manifestBytes, err := oras.FetchBytes(ctx, imageStore, signingInfoTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return "", fmt.Errorf("getting index bytes: %w", err)
	}

	manifest := &ocispec.Manifest{}
	err = json.Unmarshal(manifestBytes, manifest)
	if err != nil {
		return "", fmt.Errorf("decoding index: %w", err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType == bundleV03MediaType {
			return layer.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("signature tag not found for index %q", signingInfoTag)
}

func _loadSigningInformation(ctx context.Context, imageStore oras.GraphTarget, repo *remote.Repository, imageDigest string, format string) ([]byte, []byte, error) {
	var signingInfoTag string
	switch format {
	case legacyFormat:
		signatureTag, err := helpers.CraftCosignSignatureTag(imageDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("crafting signature tag: %w", err)
		}
		signingInfoTag = signatureTag
	case oci11Format:
		indexTag, err := helpers.CraftSignatureIndexTag(imageDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("crafting index tag: %w", err)
		}
		signingInfoTag = indexTag
	case bundleFormat:
		desc, err := imageStore.Resolve(ctx, imageDigest)
		if err != nil {
			return nil, nil, fmt.Errorf("resolving %q: %w", imageDigest, err)
		}

		descriptors, err := registry.Referrers(ctx, imageStore, desc, bundleV03MediaType)
		if err != nil {
			return nil, nil, fmt.Errorf("searching for bundle referring %q: %w", imageDigest, err)
		}

		if len(descriptors) > 1 {
			return nil, nil, errors.New("image with several bundles are not supported")
		}

		signingInfoTag = descriptors[0].Digest.String()
	default:
		return nil, nil, fmt.Errorf("signature format %q unknown, expected one in %v", format, strings.Join(supportedFormats, ","))
	}

	_, err := imageStore.Resolve(ctx, signingInfoTag)
	if err != nil {
		if err := pullCosignSigningInformation(ctx, repo, signingInfoTag, imageStore); err != nil {
			return nil, nil, fmt.Errorf("getting signing information for %q: %w", signingInfoTag, err)
		}
	}

	var signatureTag string
	switch format {
	case legacyFormat:
		signatureTag = signingInfoTag
	case oci11Format:
		signatureTag, err = getSignatureTagOci11(ctx, imageStore, signingInfoTag)
		if err != nil {
			return nil, nil, fmt.Errorf("getting OCI 1.1 signature tag: %w", err)
		}
	case bundleFormat:
		signatureTag, err = getSignatureTagBundle(ctx, imageStore, signingInfoTag)
		if err != nil {
			return nil, nil, fmt.Errorf("getting bundle signature tag: %w", err)
		}
	}

	return loadSignatureAndPayload(ctx, imageStore, signatureTag, format)
}

func loadSigningInformation(ctx context.Context, imageRef reference.Named, imageStore oras.GraphTarget, repo *remote.Repository) ([]byte, []byte, string, error) {
	imageDigest, err := helpers.GetImageDigest(ctx, imageStore, imageRef.String())
	if err != nil {
		return nil, nil, "", fmt.Errorf("getting image digest: %w", err)
	}

	errs := make([]error, 0)
	for _, format := range supportedFormats {
		signature, payload, err := _loadSigningInformation(ctx, imageStore, repo, imageDigest, format)
		if err == nil {
			return signature, payload, format, nil
		}
		errs = append(errs, fmt.Errorf("loading signing information for %q: %w", format, err))
	}

	return nil, nil, "", errors.Join(errs...)
}

func newVerifier(publicKey []byte) (signature.Verifier, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("decoding public key to PEM blocks")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading verifier: %w", err)
	}

	return verifier, nil
}

func checkPayloadImage(payloadBytes []byte, imageDigest string) error {
	payloadImage := &payload.SimpleContainerImage{}
	err := json.Unmarshal(payloadBytes, payloadImage)
	if err != nil {
		return fmt.Errorf("unmarshalling payload: %w", err)
	}

	if payloadImage.Critical.Image.DockerManifestDigest != imageDigest {
		return fmt.Errorf("payload digest does not correspond to image: expected %s, got %s", imageDigest, payloadImage.Critical.Image.DockerManifestDigest)
	}

	return nil
}

func (c *Verifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.GraphTarget, ref reference.Named) error {
	imageDigest, err := helpers.GetImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	signatureBytes, payloadBytes, format, err := loadSigningInformation(ctx, ref, imageStore, repo)
	if err != nil {
		return fmt.Errorf("getting signing information: %w", err)
	}

	verified := false
	var errs error
	for _, verifier := range c.verifiers {
		err = verifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(payloadBytes))
		if err == nil {
			verified = true

			break
		}

		errs = errors.Join(errs, err)
	}

	if !verified {
		return fmt.Errorf("the image was not signed by the provided keys: %w", errs)
	}

	if format != bundleFormat {
		// We should not read the payload before confirming it was signed, so let's
		// do this check once it was confirmed to be signed:
		// https://github.com/containers/image/blob/main/docs/containers-signature.5.md#the-cryptographic-signature
		err = checkPayloadImage(payloadBytes, imageDigest)
		if err != nil {
			return fmt.Errorf("checking payload image: %w", err)
		}
	}

	return nil
}

func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	keys := len(opts.PublicKeys)
	if keys == 0 {
		return nil, errors.New("no public keys given")
	}

	verifier := &Verifier{
		verifiers: make([]signature.Verifier, keys),
	}

	for i, publicKey := range opts.PublicKeys {
		verif, err := newVerifier([]byte(publicKey))
		if err != nil {
			return nil, fmt.Errorf("creating verifier for %s: %w", publicKey, err)
		}

		verifier.verifiers[i] = verif
	}

	return verifier, nil
}
