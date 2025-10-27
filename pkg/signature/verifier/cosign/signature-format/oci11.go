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

// Taken from:
// https://github.com/sigstore/cosign/blob/45bda40b8ef4/internal/pkg/oci/remote/remote.go#L24
const signatureArtifactType = "application/vnd.dev.cosign.artifact.sig.v1+json"

type OCI11Format struct{}

func (*OCI11Format) CraftSigningInfoTag(imageDigest string) (string, error) {
	return helpers.CraftSignatureIndexTag(imageDigest)
}

func (*OCI11Format) FindSignatureTag(ctx context.Context, imageStore oras.GraphTarget, signingInfoTag string) (string, error) {
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

func (*OCI11Format) LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, error) {
	return loadSignatureAndPayload(ctx, imageStore, signatureTag)
}

func (*OCI11Format) Name() string {
	return "oci 1.1"
}
