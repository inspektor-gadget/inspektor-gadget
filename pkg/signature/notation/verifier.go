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

package notation

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/distribution/reference"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"
)

type VerifierOptions struct {
	Certificates   []string
	PolicyDocument string
}

type Verifier struct {
	notation.Verifier
}

const maxSignatureAttempts = 50

func getImageDigest(ctx context.Context, store oras.Target, imageRef string) (string, error) {
	desc, err := store.Resolve(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	return desc.Digest.String(), nil
}

func getAndValidateTrustPolicy(policy string) (*trustpolicy.Document, error) {
	policyDocument := &trustpolicy.Document{}
	if err := json.Unmarshal([]byte(policy), policyDocument); err != nil {
		return nil, fmt.Errorf("unmarshalling trust policy Document: %w", err)
	}

	if err := policyDocument.Validate(); err != nil {
		return nil, fmt.Errorf("validating policy document: %w", err)
	}

	// This comes as a limitation on how certificates are given on the CLI,
	// as we do not know to which trust store they should belong, we all store
	// them in the same trust store.
	if len(policyDocument.TrustPolicies[0].TrustStores) > 1 {
		return nil, errors.New("trust policies with multiple trust stores are unsupported")
	}

	return policyDocument, nil
}

func addCertificatesToTrustStore(trustStore string, certificates []string) (string, error) {
	trustStoreDir, err := os.MkdirTemp("", "ig-trust-store-")
	if err != nil {
		return "", err
	}
	path := filepath.Join(trustStoreDir, "truststore", "x509", trustStore)
	if err := os.MkdirAll(path, 0o700); err != nil {
		return "", err
	}

	for i, certificate := range certificates {
		if err := os.WriteFile(filepath.Join(path, fmt.Sprintf("certificate_%d.pem", i)), []byte(certificate), 0o600); err != nil {
			return "", err
		}
	}

	return trustStoreDir, nil
}

func NewVerifier(opts VerifierOptions) (*Verifier, error) {
	if len(opts.Certificates) == 0 {
		return nil, errors.New("no certificates given")
	}

	policy, err := getAndValidateTrustPolicy(opts.PolicyDocument)
	if err != nil {
		return nil, fmt.Errorf("getting and validating trust policy: %w", err)
	}

	parts := strings.Split(policy.TrustPolicies[0].TrustStores[0], ":")

	// Above call to Validate() ensure there are two parts:
	// https://github.com/notaryproject/notation-go/blob/e83edbc388a9/verifier/trustpolicy/trustpolicy.go#L308-L311
	// Moreover, using filepath.Join() is OK, as the name should respect this
	// regexp ^[a-zA-Z0-9_.-]+$:
	// https://github.com/notaryproject/notation-go/blob/e83edbc388a9/internal/file/file.go#L39-L41
	trustStore := filepath.Join(parts[0], parts[1])
	trustStoreDir, err := addCertificatesToTrustStore(trustStore, opts.Certificates)
	if err != nil {
		return nil, fmt.Errorf("adding certificates to trust store: %w", err)
	}

	verif, err := verifier.New(policy, truststore.NewX509TrustStore(dir.NewSysFS(trustStoreDir)), nil)
	if err != nil {
		return nil, err
	}

	return &Verifier{verif}, nil
}

func (n *Verifier) Verify(ctx context.Context, _ *remote.Repository, imageStore oras.GraphTarget, ref reference.Named) error {
	imageDigest, err := getImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	verifyOptions := notation.VerifyOptions{
		ArtifactReference:    fmt.Sprintf("%s@%s", ref.Name(), imageDigest),
		MaxSignatureAttempts: maxSignatureAttempts,
	}
	_, _, err = notation.Verify(ctx, n.Verifier, registry.NewRepository(imageStore), verifyOptions)

	return err
}
