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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	securejoin "github.com/cyphar/filepath-securejoin"
	"github.com/distribution/reference"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	"github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/verifier"
	"github.com/notaryproject/notation-go/verifier/trustpolicy"
	"github.com/notaryproject/notation-go/verifier/truststore"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/registry/remote"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

type NotationVerifyOptions struct {
	Certificates   []string
	PolicyDocument string
}

type notationVerifier struct {
	certificates   []string
	policyDocument string
}

const maxSignatureAttempts = 50

func getAndValidateTrustPolicy(policy string) (*trustpolicy.Document, error) {
	policyDocument := &trustpolicy.Document{}
	if err := json.Unmarshal([]byte(policy), policyDocument); err != nil {
		return nil, fmt.Errorf("unmarshalling trust policy Document: %w", err)
	}

	if len(policyDocument.TrustPolicies) == 0 {
		return nil, errors.New("no trust policies given")
	}

	if len(policyDocument.TrustPolicies) > 1 {
		return nil, errors.New("multiple trust policies are unsupported")
	}

	if len(policyDocument.TrustPolicies[0].TrustStores) > 1 {
		return nil, errors.New("trust policies with multiple trust stores are unsupported")
	}

	return policyDocument, nil
}

func getTrustStore(rawTrustStore string) (string, error) {
	// In the policy document, trust stores are given as "type:name":
	// https://github.com/notaryproject/specifications/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-policy
	// which then corresponds to type/name in the filesystem:
	// https://github.com/notaryproject/specifications/blob/v1.0.0/specs/trust-store-trust-policy.md#trust-store
	parts := strings.Split(rawTrustStore, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong trust store name, expected type:name, got: %q", rawTrustStore)
	}

	return securejoin.SecureJoin(host.HostRoot, filepath.Join(parts[0], parts[1]))
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

// Mainly inspired by:
// https://github.com/notaryproject/notation-go/blob/6063ebe30f96/example_remoteVerify_test.go#L34
func (n *notationVerifier) Verify(ctx context.Context, repo *remote.Repository, imageStore oras.Target, ref reference.Named) error {
	imageDigest, err := getImageDigest(ctx, imageStore, ref.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	policy, err := getAndValidateTrustPolicy(n.policyDocument)
	if err != nil {
		return fmt.Errorf("getting and validating trust policy: %w", err)
	}

	trustStore, err := getTrustStore(policy.TrustPolicies[0].TrustStores[0])
	if err != nil {
		return fmt.Errorf("getting and validating trust store: %w", err)
	}

	trustStoreDir, err := addCertificatesToTrustStore(trustStore, n.certificates)
	if err != nil {
		return fmt.Errorf("adding certificates to trust store: %w", err)
	}

	verifier, err := verifier.New(policy, truststore.NewX509TrustStore(dir.NewSysFS(trustStoreDir)), nil)
	if err != nil {
		return err
	}

	verifyOptions := notation.VerifyOptions{
		ArtifactReference:    fmt.Sprintf("%s@%s", ref.Name(), imageDigest),
		MaxSignatureAttempts: maxSignatureAttempts,
	}
	_, _, err = notation.Verify(ctx, verifier, registry.NewRepository(repo), verifyOptions)

	return err
}
