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
	"encoding/base64"
	"encoding/json"
	"fmt"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
)

// Taken from:
// https://github.com/sigstore/cosign/blob/45bda40b8ef4/pkg/types/media.go#L28
const simpleSigningMediaType = "application/vnd.dev.cosign.simplesigning.v1+json"

type SignatureFormat interface {
	CheckPayloadImage(payloadBytes []byte, imageDigest string) error
	CraftSigningInfoTag(imageDigest string) (string, error)
	FindSignatureTag(ctx context.Context, imageStore oras.GraphTarget, signingInfoTag string) (string, error)
	LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, []byte, error)
	Name() string
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

func loadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, []byte, error) {
	_, signatureManifestBytes, err := oras.FetchBytes(ctx, imageStore, signatureTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting signature bytes: %w", err)
	}

	signatureManifest := &ocispec.Manifest{}
	err = json.Unmarshal(signatureManifestBytes, signatureManifest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding signature manifest: %w", err)
	}

	layers := signatureManifest.Layers
	expectedLen := 1
	layersLen := len(layers)
	if layersLen != expectedLen {
		return nil, nil, nil, fmt.Errorf("wrong number of signature manifest layers: expected %d, got %d", expectedLen, layersLen)
	}

	payloadDescriptor := layers[0]
	if payloadDescriptor.MediaType != simpleSigningMediaType {
		return nil, nil, nil, fmt.Errorf("wrong payloadDescriptor media type: expected %s, got %s", simpleSigningMediaType, payloadDescriptor.MediaType)
	}

	signature, ok := payloadDescriptor.Annotations["dev.cosignproject.cosign/signature"]
	if !ok {
		return nil, nil, nil, fmt.Errorf("no signature in payloadDescriptor")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding signature: %w", err)
	}

	payloadBytes, err := content.FetchAll(ctx, imageStore, payloadDescriptor)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting payload bytes: %w", err)
	}

	return signatureBytes, payloadBytes, payloadBytes, nil
}
