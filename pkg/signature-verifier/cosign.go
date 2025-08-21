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

package signatureverifier

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
	log "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
)

type CosignVerifyOptions struct {
	PublicKeys []string
}

type cosignVerifier struct {
	publicKeys []string
}

func getImageDigest(ctx context.Context, store oras.Target, imageRef string) (string, error) {
	desc, err := store.Resolve(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	return desc.Digest.String(), nil
}

func craftCosignSignatureTag(digest string) (string, error) {
	// WARNING: cosign is considering changing the scheme for
	// publishing/retrieving sigstore bundles to/from an OCI registry, see:
	// https://sigstore.slack.com/archives/C0440BFT43H/p1712253122721879?thread_ts=1712238666.552719&cid=C0440BFT43H
	// https://github.com/sigstore/cosign/pull/3622
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong digest, expected two parts, got %d", len(parts))
	}

	return fmt.Sprintf("%s-%s.sig", parts[0], parts[1]), nil
}

func pullCosignSigningInformation(ctx context.Context, repo *remote.Repository, imageDigest string, imageStore oras.Target) error {
	signatureTag, err := craftCosignSignatureTag(imageDigest)
	if err != nil {
		return fmt.Errorf("crafting signature tag: %w", err)
	}
	// copy the signature and payload from repo:signatureTag to imageStore
	if _, err = oras.Copy(ctx, repo, signatureTag, imageStore, signatureTag, oras.DefaultCopyOptions); err != nil {
		return fmt.Errorf("copying signature tag %q: %w", signatureTag, err)
	}

	return nil
}

func loadSignature(ctx context.Context, repo oras.Target, signatureTag string) ([]byte, *ocispec.Descriptor, error) {
	_, signatureManifestBytes, err := oras.FetchBytes(ctx, repo, signatureTag, oras.DefaultFetchBytesOptions)
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
	// Taken from:
	// https://github.com/sigstore/cosign/blob/e23dcd11f24b729f6ff9300ab7a61b09d71da12a/pkg/types/media.go#L28
	expectedMediaType := "application/vnd.dev.cosign.simplesigning.v1+json"
	if payloadDescriptor.MediaType != expectedMediaType {
		return nil, nil, fmt.Errorf("wrong payloadDescriptor media type: expected %s, got %s", expectedMediaType, payloadDescriptor.MediaType)
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

func loadPayload(ctx context.Context, repo oras.Target, payloadDescriptor *ocispec.Descriptor) ([]byte, error) {
	payloadBytes, err := content.FetchAll(ctx, repo, *payloadDescriptor)
	if err != nil {
		return nil, fmt.Errorf("getting payload bytes: %w", err)
	}

	return payloadBytes, nil
}

func loadSigningInformation(ctx context.Context, imageRef reference.Named, imageStore oras.Target, repo *remote.Repository) ([]byte, []byte, error) {
	imageDigest, err := getImageDigest(ctx, imageStore, imageRef.String())
	if err != nil {
		return nil, nil, fmt.Errorf("getting image digest: %w", err)
	}

	signatureTag, err := craftCosignSignatureTag(imageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("crafting signature tag: %w", err)
	}

	if _, err := imageStore.Resolve(ctx, signatureTag); err != nil {
		// it's possible that users pulled the image with an ig version
		// that doesn't pulls the signature too, so we need to pull it here to
		// avoid breaking them.
		// TODO: This code could be removed in v0.45.0
		if !errors.Is(err, errdef.ErrNotFound) {
			return nil, nil, fmt.Errorf("resolving signature tag %q: %w", signatureTag, err)
		}

		log.Debugf("Signature tag %q not found in local store, pulling it", signatureTag)
		if err := pullCosignSigningInformation(ctx, repo, imageDigest, imageStore); err != nil {
			return nil, nil, fmt.Errorf("copying signature tag %q: %w", signatureTag, err)
		}
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

func (c *cosignVerifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error {
	imageDigest, err := getImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	signatureBytes, payloadBytes, err := loadSigningInformation(ctx, ref, imageStore, repo)
	if err != nil {
		return fmt.Errorf("getting signing information: %w", err)
	}

	verified := false
	var errs error
	for _, publicKey := range c.publicKeys {
		verifier, err := newVerifier([]byte(publicKey))
		if err != nil {
			return fmt.Errorf("creating verifier for %s: %w", publicKey, err)
		}

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
