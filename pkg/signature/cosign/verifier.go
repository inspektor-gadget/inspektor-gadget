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
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"

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
	// https://github.com/sigstore/cosign/blob/45bda40b8ef4/pkg/types/media.go#L28
	simpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"
)

func craftCosignSignatureTag(digest string) (string, error) {
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong digest, expected two parts, got %d", len(parts))
	}

	return fmt.Sprintf("%s-%s.sig", parts[0], parts[1]), nil
}

func loadSignature(ctx context.Context, imageStore oras.Target, signatureTag string) ([]byte, *ocispec.Descriptor, error) {
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

	return signatureBytes, &payloadDescriptor, nil
}

func loadPayload(ctx context.Context, imageStore oras.Target, payloadDescriptor *ocispec.Descriptor) ([]byte, error) {
	payloadBytes, err := content.FetchAll(ctx, imageStore, *payloadDescriptor)
	if err != nil {
		return nil, fmt.Errorf("getting payload bytes: %w", err)
	}

	return payloadBytes, nil
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

func _loadSigningInformation(ctx context.Context, imageStore oras.Target, repo *remote.Repository, signingInfoTag string, useOCI11 bool) ([]byte, []byte, error) {
	_, err := imageStore.Resolve(ctx, signingInfoTag)
	if err != nil {
		if err := pullCosignSigningInformation(ctx, repo, signingInfoTag, imageStore); err != nil {
			return nil, nil, fmt.Errorf("getting signing information for %q: %w", signingInfoTag, err)
		}
	}

	var signatureTag string
	if useOCI11 {
		signatureTag, err = getSignatureTagOci11(ctx, imageStore, signingInfoTag)
		if err != nil {
			return nil, nil, fmt.Errorf("getting OCI 1.1 signature tag: %w", err)
		}
	} else {
		signatureTag = signingInfoTag
	}

	signature, payloadTag, err := loadSignature(ctx, imageStore, signatureTag)
	if err != nil {
		return nil, nil, fmt.Errorf("getting signature: %w", err)
	}

	payload, err := loadPayload(ctx, imageStore, payloadTag)
	if err != nil {
		return nil, nil, fmt.Errorf("getting payload: %w", err)
	}

	return signature, payload, nil
}

func loadSigningInformation(ctx context.Context, imageRef reference.Named, imageStore oras.Target, repo *remote.Repository) ([]byte, []byte, error) {
	imageDigest, err := helpers.GetImageDigest(ctx, imageStore, imageRef.String())
	if err != nil {
		return nil, nil, fmt.Errorf("getting image digest: %w", err)
	}

	signatureTag, err := craftCosignSignatureTag(imageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("crafting signature tag: %w", err)
	}

	signature, payload, loadSignatureTagErr := _loadSigningInformation(ctx, imageStore, repo, signatureTag, false)
	if loadSignatureTagErr == nil {
		return signature, payload, nil
	}

	indexTag, err := helpers.CraftSignatureIndexTag(imageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("crafting index tag: %w", err)
	}

	signature, payload, loadIndexTagErr := _loadSigningInformation(ctx, imageStore, repo, indexTag, true)
	if loadIndexTagErr == nil {
		return signature, payload, nil
	}

	return nil, nil, errors.Join(loadSignatureTagErr, loadIndexTagErr)
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

	signatureBytes, payloadBytes, err := loadSigningInformation(ctx, ref, imageStore, repo)
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

	// We should not read the payload before confirming it was signed, so let's
	// do this check once it was confirmed to be signed:
	// https://github.com/containers/image/blob/main/docs/containers-signature.5.md#the-cryptographic-signature
	err = checkPayloadImage(payloadBytes, imageDigest)
	if err != nil {
		return fmt.Errorf("checking payload image: %w", err)
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
