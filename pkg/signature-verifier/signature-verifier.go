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
	"errors"
	"fmt"

	"github.com/distribution/reference"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

type VerifyOptions struct {
	CosignVerifyOptions
}

type Verifier interface {
	Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error
}

func ExportSigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, desc ocispec.Descriptor) error {
	signatureTag, err := craftCosignSignatureTag(desc.Digest.String())
	if err != nil {
		return fmt.Errorf("crafting signature tag: %w", err)
	}

	_, err = oras.Copy(ctx, src, signatureTag, dst, signatureTag, oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("copying signature to remote repository: %w", err)
	}

	return nil
}

func PullSigningInformation(ctx context.Context, repo *remote.Repository, imageStore oras.Target, digest string) error {
	return pullCosignSigningInformation(ctx, repo, digest, imageStore)
}

func Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named, opts VerifyOptions) error {
	if len(opts.PublicKeys) == 0 {
		return errors.New("no public keys given")
	}

	verifier := cosignVerifier{
		publicKeys: opts.PublicKeys,
	}

	err := verifier.Verify(ctx, repo, imageStore, ref)
	if err != nil {
		return fmt.Errorf("verifying with cosign: %w", err)
	}

	return nil
}
