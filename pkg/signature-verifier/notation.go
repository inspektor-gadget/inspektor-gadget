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
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/distribution/reference"
	"github.com/notaryproject/notation-core-go/signature"
	"github.com/notaryproject/notation-core-go/signature/cose"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go/registry"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/registry/remote"
)

type NotationVerifyOptions struct {
	Certificates []string
}

type notationVerifier struct {
	certificates []string
}

const (
	// Taken from:
	// https://github.com/notaryproject/notation-go/blob/e83edbc388a9/internal/envelope/envelope.go#L27C2-L28C2
	mediaTypePayloadV1 = "application/vnd.cncf.notary.payload.v1+json"

	referrersPagesLimit = 42

	// From some check, the size is 726 bytes, let's take the immediate bigger
	// power of two.
	manifestMaxSize = 1024
)

func getSignatures(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) (map[string][][]byte, error) {
	desc, err := imageStore.Resolve(ctx, ref.String())
	if err != nil {
		return nil, fmt.Errorf("resolving image %q: %w", ref, err)
	}

	signatures := map[string][][]byte{
		jws.MediaTypeEnvelope:  make([][]byte, 0),
		cose.MediaTypeEnvelope: make([][]byte, 0),
	}

	referrersPagesCount := 0
	err = repo.Referrers(ctx, desc, registry.ArtifactTypeNotation, func(references []ocispec.Descriptor) error {
		if referrersPagesCount > referrersPagesLimit {
			return fmt.Errorf("too many referrers pages for %q: %d", ref.String(), referrersPagesLimit)
		}

		referrersPagesCount++

		for _, reference := range references {
			if reference.Size > manifestMaxSize {
				continue
			}

			bytes, err := content.FetchAll(ctx, repo, reference)
			if err != nil {
				return fmt.Errorf("getting signature manifest bytes: %w", err)
			}

			signatureManifest := &ocispec.Manifest{}
			err = json.Unmarshal(bytes, signatureManifest)
			if err != nil {
				return fmt.Errorf("decoding signature manifest: %w", err)
			}

			for _, layer := range signatureManifest.Layers {
				if layer.MediaType != cose.MediaTypeEnvelope && layer.MediaType != jws.MediaTypeEnvelope {
					continue
				}

				signatureBytes, err := content.FetchAll(ctx, repo, layer)
				if err != nil {
					return fmt.Errorf("getting signature bytes: %w", err)
				}

				signatures[layer.MediaType] = append(signatures[layer.MediaType], signatureBytes)
			}
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("ranging through referrers: %w", err)
	}

	return signatures, nil
}

// Inspired by:
// https://github.com/notaryproject/notation-go/blob/6063ebe30f96b0830e1385db4cdcdc24b0536d1a/verifier/verifier.go#L681
func verifyIntegrity(mediaTypeEnvelope string, signatureBytes []byte) (*signature.EnvelopeContent, error) {
	if mediaTypeEnvelope != cose.MediaTypeEnvelope && mediaTypeEnvelope != jws.MediaTypeEnvelope {
		return nil, fmt.Errorf("wrong media type envelope, expected %q or %q, got: %q", cose.MediaTypeEnvelope, jws.MediaTypeEnvelope, mediaTypeEnvelope)
	}

	envelope, err := signature.ParseEnvelope(mediaTypeEnvelope, signatureBytes)
	if err != nil {
		return nil, fmt.Errorf("parsing envelope: %w", err)
	}

	content, err := envelope.Verify()
	if err != nil {
		return nil, fmt.Errorf("verifying envelope: %w", err)
	}

	if content.Payload.ContentType != mediaTypePayloadV1 {
		return nil, fmt.Errorf("bad payload content type, expected %q, got: %q", mediaTypePayloadV1, content.Payload.ContentType)
	}

	return content, nil
}

func (n *notationVerifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error {
	certificates := make([]*x509.Certificate, len(n.certificates))
	for _, certificate := range n.certificates {
		block, _ := pem.Decode([]byte(certificate))
		if block == nil {
			return fmt.Errorf("decoding certificate to PEM blocks")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("parsing certificate: %w", err)
		}

		certificates = append(certificates, cert)
	}

	signatures, err := getSignatures(ctx, repo, imageStore, ref)
	if err != nil {
		return fmt.Errorf("getting signature bytes: %w", err)
	}

	if len(signatures[jws.MediaTypeEnvelope]) == 0 && len(signatures[cose.MediaTypeEnvelope]) == 0 {
		return errors.New("no signatures were found")
	}

	for mediaTypeEnvelope, signaturesBytes := range signatures {
		for _, signatureBytes := range signaturesBytes {
			content, err := verifyIntegrity(mediaTypeEnvelope, signatureBytes)
			if err != nil {
				return fmt.Errorf("verifying envelope integrity: %w", err)
			}

			_, err = signature.VerifyAuthenticity(&content.SignerInfo, certificates)
			if err != nil {
				return fmt.Errorf("verifying signature authenticity: %w", err)
			}
		}
	}

	return nil
}
