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

package signature

import (
	"context"
	"errors"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/cosign"
)

type Verifier interface {
	Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error
}

type SignatureVerifier struct {
	*cosign.Verifier
}

type VerifierOptions struct {
	CosignVerifierOpts cosign.VerifierOptions
}

func (v *SignatureVerifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error {
	if v.Verifier == nil {
		return errors.New("no verification method available")
	}

	return v.Verifier.Verify(ctx, repo, imageStore, ref)
}

func ExportSigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, desc ocispec.Descriptor) error {
	return cosign.ExportSigningInformation(ctx, src, dst, desc)
}

func PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	return cosign.PullSigningInformation(ctx, repo, imageStore, digest)
}

func NewSignatureVerifier(opts VerifierOptions) (*SignatureVerifier, error) {
	cosignVerifier, err := cosign.NewVerifier(opts.CosignVerifierOpts)
	return &SignatureVerifier{cosignVerifier}, err
}
