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

package verifier

import (
	"context"
	"errors"
	"fmt"

	"github.com/distribution/reference"
	"oras.land/oras-go/v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/verifier/cosign"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/verifier/notation"
)

type Verifier interface {
	Verify(ctx context.Context, imageStore oras.GraphTarget, ref reference.Named) error
}

type SignatureVerifier struct {
	verifiers map[string]Verifier
}

type VerifierOptions struct {
	CosignVerifierOpts   cosign.VerifierOptions
	NotationVerifierOpts notation.VerifierOptions
}

func (v *SignatureVerifier) Verify(ctx context.Context, imageStore oras.GraphTarget, ref reference.Named) error {
	if len(v.verifiers) == 0 {
		return errors.New("no verification method available")
	}

	errs := make([]error, 0)
	for method, verifier := range v.verifiers {
		err := verifier.Verify(ctx, imageStore, ref)
		if err == nil {
			return nil
		}

		errs = append(errs, fmt.Errorf("verifying with %s: %w", method, err))
	}

	return errors.Join(errs...)
}

func NewSignatureVerifier(opts VerifierOptions) (*SignatureVerifier, error) {
	ret := &SignatureVerifier{verifiers: make(map[string]Verifier)}

	if len(opts.CosignVerifierOpts.PublicKeys) > 0 {
		verifier, err := cosign.NewVerifier(opts.CosignVerifierOpts)
		if err != nil {
			return nil, fmt.Errorf("creating cosign verifier: %w", err)
		}

		ret.verifiers["cosign"] = verifier
	}

	if len(opts.NotationVerifierOpts.Certificates) > 0 && len(opts.NotationVerifierOpts.PolicyDocument) > 0 {
		verifier, err := notation.NewVerifier(opts.NotationVerifierOpts)
		if err != nil {
			return nil, fmt.Errorf("creating notation verifier: %w", err)
		}

		ret.verifiers["notation"] = verifier
	}

	return ret, nil
}
