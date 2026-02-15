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
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

type OCI11Format struct{}

func (*OCI11Format) CheckPayloadImage(payloadBytes []byte, imageDigest string) error {
	return checkPayloadImage(payloadBytes, imageDigest)
}

func (*OCI11Format) CraftSigningInfoTag(imageDigest string) (string, error) {
	// The OCI 1.1 format uses the image digest to find referrers in the registry,
	// not a tag.
	// Return the imageDigest here, since the logic for finding the signature tag
	// is handled in FindSignatureTag().
	return imageDigest, nil
}

func (*OCI11Format) FindSignatureTag(ctx context.Context, imageStore oras.GraphTarget, imageDigest string) (string, error) {
	// Let's first try finding the tag using the referrers API and then default
	// to sha256-digest tag.
	signingInfoTag, err := helpers.FindCosignSignatureTag(ctx, imageStore, imageDigest)
	if err == nil {
		return signingInfoTag, nil
	}

	signingInfoTag, err = helpers.CraftSignatureIndexTag(imageDigest)
	if err != nil {
		return "", fmt.Errorf("finding signature tag using referrers API and tag: %w", err)
	}

	_, indexBytes, err := oras.FetchBytes(ctx, imageStore, signingInfoTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return "", fmt.Errorf("getting manifest bytes: %w", err)
	}

	index := &ocispec.Index{}
	err = json.Unmarshal(indexBytes, index)
	if err != nil {
		return "", fmt.Errorf("decoding index: %w", err)
	}

	// With the sha256-digest tag, we get an index, we then need to find the
	// corresponding manifest from this index.
	for _, manifest := range index.Manifests {
		if manifest.ArtifactType == helpers.CosignSignatureMediaType {
			return manifest.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("signature tag not found for index %q", signingInfoTag)
}

func (*OCI11Format) LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, []byte, error) {
	return loadSignatureAndPayload(ctx, imageStore, signatureTag)
}

func (*OCI11Format) Name() string {
	return "oci 1.1"
}
