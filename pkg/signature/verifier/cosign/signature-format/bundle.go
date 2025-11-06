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

	intoto "github.com/in-toto/in-toto-golang/in_toto"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/secure-systems-lab/go-securesystemslib/dsse"
	sigstorebundle "github.com/sigstore/protobuf-specs/gen/pb-go/bundle/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

type BundleFormat struct{}

func (*BundleFormat) CheckPayloadImage(payloadBytes []byte, imageDigest string) error {
	var statement intoto.Statement
	err := json.Unmarshal(payloadBytes, &statement)
	if err != nil {
		return fmt.Errorf("unmarshalling payload: %w", err)
	}

	if len(statement.Subject) == 0 {
		return fmt.Errorf("payload has no subject: %v", statement)
	}

	for algorithm, hash := range statement.Subject[0].Digest {
		digest := fmt.Sprintf("%s:%s", algorithm, hash)
		if digest == imageDigest {
			return nil
		}
	}

	return fmt.Errorf("payload digest does not correspond to image: expected %s", imageDigest)
}

func (*BundleFormat) CraftSigningInfoTag(imageDigest string) (string, error) {
	// The bundle format uses the image digest to find referrers in the registry,
	// not a tag.
	// Return the imageDigest here, since the logic for finding the signature tag
	// is handled in FindSignatureTag().
	return imageDigest, nil
}

func (*BundleFormat) FindSignatureTag(ctx context.Context, imageStore oras.GraphTarget, imageDigest string) (string, error) {
	signingInfoTag, err := helpers.FindBundleTag(ctx, imageStore, imageDigest)
	if err != nil {
		return "", fmt.Errorf("finding bundle tag for %q: %w", imageDigest, err)
	}

	_, manifestBytes, err := oras.FetchBytes(ctx, imageStore, signingInfoTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return "", fmt.Errorf("getting manifest bytes: %w", err)
	}

	manifest := &ocispec.Manifest{}
	err = json.Unmarshal(manifestBytes, manifest)
	if err != nil {
		return "", fmt.Errorf("decoding manifest: %w", err)
	}

	for _, layer := range manifest.Layers {
		if layer.MediaType == helpers.BundleV03MediaType {
			return layer.Digest.String(), nil
		}
	}

	return "", fmt.Errorf("signature tag not found for index %q", signingInfoTag)
}

func (*BundleFormat) LoadSignatureAndPayload(ctx context.Context, imageStore oras.GraphTarget, signatureTag string) ([]byte, []byte, []byte, error) {
	_, bundleBytes, err := oras.FetchBytes(ctx, imageStore, signatureTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("getting bundle bytes: %w", err)
	}

	bundle := &sigstorebundle.Bundle{}
	err = protojson.Unmarshal(bundleBytes, bundle)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("decoding bundle: %w", err)
	}

	envelope := bundle.GetDsseEnvelope()
	if envelope == nil {
		return nil, nil, nil, errors.New("DSSE envelope not found in bundle")
	}

	signatures := envelope.GetSignatures()
	expectedLen := 1
	signaturesLen := len(signatures)
	if signaturesLen != expectedLen {
		return nil, nil, nil, fmt.Errorf("wrong number of signatures: expected %d, got %d", expectedLen, signaturesLen)
	}

	rawPayload := envelope.GetPayload()

	return signatures[0].Sig, dsse.PAE(envelope.GetPayloadType(), rawPayload), rawPayload, nil
}

func (*BundleFormat) Name() string {
	return "bundle"
}
