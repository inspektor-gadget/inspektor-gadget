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
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/distribution/reference"
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
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
	&signatureformat.LegacyFormat{},
	&signatureformat.OCI11Format{},
}

func loadSigningInformation(ctx context.Context, imageDigest string, imageStore oras.GraphTarget) ([]byte, []byte, error) {
	errs := make([]error, 0)
	for _, format := range supportedFormats {
		signingInfoTag, err := format.CraftSigningInfoTag(imageDigest)
		if err != nil {
			errs = append(errs, fmt.Errorf("crafting signing info tag for %s format: %w", format.Name(), err))

			continue
		}

		signatureTag, err := format.FindSignatureTag(ctx, imageStore, signingInfoTag)
		if err != nil {
			errs = append(errs, fmt.Errorf("finding signature tag for %s format: %w", format.Name(), err))

			continue
		}

		signature, payload, err := format.LoadSignatureAndPayload(ctx, imageStore, signatureTag)
		if err != nil {
			errs = append(errs, fmt.Errorf("loading signature and payload for %s format: %w", format.Name(), err))

			continue
		}

		return signature, payload, nil
	}

	return nil, nil, errors.Join(errs...)
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

func (c *Verifier) Verify(ctx context.Context, imageStore oras.GraphTarget, ref reference.Named) error {
	imageDigest, err := helpers.GetImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	signatureBytes, payloadBytes, err := loadSigningInformation(ctx, imageDigest, imageStore)
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
