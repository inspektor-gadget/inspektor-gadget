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

package signatureformat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	sigstorebundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2/registry"
)

// Taken from:
// https://github.com/sigstore/cosign/blob/ee3d9fe1c55e/pkg/cosign/bundle/protobundle.go#L36
const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type BundleFormat struct{}

func (BundleFormat) CraftSigningInfoTag(imageDigest string) (string, error) {
	// The bundle format uses the image digest to find referrers in the registry, not a tag.
	// Let's return the imageDigest here to reuse it in Return empty, since logic is handled in FindSignatureTag.
	return imageDigest, nil
}

func (BundleFormat) FindSignatureTag(ctx context.Context, imageStore oras.GraphTarget, imageDigest string) (string, error) {
	desc, err := imageStore.Resolve(ctx, imageDigest)
	if err != nil {
		return "", fmt.Errorf("resolving %q: %w", imageDigest, err)
	}

	descriptors, err := registry.Referrers(ctx, imageStore, desc, bundleV03MediaType)
	if err != nil {
		return "", fmt.Errorf("searching for bundle referring %q: %w", imageDigest, err)
	}

	if len(descriptors) == 0 {
		// With bundle, there is no way to retrieve the associated bundle with a tag
		// like what can be done with legacy .sig and OCI 1.1 format.
		// TODO: Write the association (imageDigest, signingInfoTag), in a file and
		// read this file when offline.

		return "", errors.New("no bundle found")
	}

	if len(descriptors) > 1 {
		return "", errors.New("image with several bundles are not supported")
	}

	signingInfoTag := descriptors[0].Digest.String()
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

func (BundleFormat) LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, error) {
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

func (BundleFormat) Name() string {
	return "bundle"
}
