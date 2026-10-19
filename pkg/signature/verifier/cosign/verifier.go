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
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/distribution/reference"
	"github.com/sigstore/sigstore/pkg/signature"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
	signatureformat "github.com/inspektor-gadget/inspektor-gadget/pkg/signature/verifier/cosign/signature-format"
)

type VerifierOptions struct {
	PublicKeys []string
}

type Verifier struct {
	verifiers []signature.Verifier
}

var supportedFormats = []signatureformat.SignatureFormat{
	&signatureformat.BundleFormat{},
	&signatureformat.LegacyFormat{},
	&signatureformat.OCI11Format{},
}

func loadSigningInformation(ctx context.Context, imageDigest string, imageStore oras.GraphTarget, format signatureformat.SignatureFormat) ([]byte, []byte, []byte, error) {
	signingInfoTag, err := format.CraftSigningInfoTag(imageDigest)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("crafting signing info tag: %w", err)
	}

	signatureTag, err := format.FindSignatureTag(ctx, imageStore, signingInfoTag)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("finding signature tag: %w", err)
	}

	return format.LoadSignatureAndPayload(ctx, imageStore, signatureTag)
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

func (c *Verifier) Verify(ctx context.Context, imageStore oras.GraphTarget, ref reference.Named) error {
	imageDigest, err := helpers.GetImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	var errs error
	for _, format := range supportedFormats {
		sig, payload, rawPayload, err := loadSigningInformation(ctx, imageDigest, imageStore, format)
		if err != nil {
			errs = errors.Join(errs, fmt.Errorf("loading %s format: %w", format.Name(), err))
			continue
		}

		for _, verifier := range c.verifiers {
			err := verifier.VerifySignature(bytes.NewReader(sig), bytes.NewReader(payload))
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("verifying %s format: %w", format.Name(), err))
				continue
			}

			// We should not read the payload before confirming it was signed:
			// https://github.com/containers/image/blob/main/docs/containers-signature.5.md#the-cryptographic-signature
			err = format.CheckPayloadImage(rawPayload, imageDigest)
			if err != nil {
				errs = errors.Join(errs, fmt.Errorf("checking %s payload image: %w", format.Name(), err))
				break
			}

			return nil
		}
	}

	return fmt.Errorf("the image was not signed by the provided keys: %w", errs)
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
