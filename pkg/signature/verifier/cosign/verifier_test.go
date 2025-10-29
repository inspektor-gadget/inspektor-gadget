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
	"context"
	"path/filepath"
	"testing"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
)

func TestNewVerifier(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		opts      VerifierOptions
		shouldErr bool
	}

	publicKey0 := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn6u8dLv8gnPGFEoAeeRXZ9r1QUqu
vxvpnBNH+Gwent1O0IisyCeEYEeGAOVcmqCLFywoF62CUMZIex/Xw56nfw==
-----END PUBLIC KEY-----
`
	publicKey1 := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIur1/9dgnL6gwRsXRoE5tgpiZX0V
wE3h/OMa2IqglFFvk8Qh1EX9zr5aASFdRcTKScjrU7uS1y6Z1z3NQe2P+g==
-----END PUBLIC KEY-----
`

	tests := map[string]testDefinition{
		"no_public_key": {
			shouldErr: true,
		},
		"malformed_public_key": {
			opts: VerifierOptions{
				PublicKeys: []string{"foobar"},
			},
			shouldErr: true,
		},
		"correct_public_key": {
			opts: VerifierOptions{
				PublicKeys: []string{publicKey0},
			},
		},
		"correct_public_keys": {
			opts: VerifierOptions{
				PublicKeys: []string{
					publicKey0,
					publicKey1,
				},
			},
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := NewVerifier(test.opts)
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestVerify(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		opts      VerifierOptions
		image     string
		shouldErr bool
	}

	legacySignedImage := "ttl.sh/signed_with_cosign_legacy:latest"
	oci11SignedImage := "ttl.sh/signed_with_cosign_oci11:latest"
	bundleSignedImage := "ttl.sh/signed_with_cosign_bundle:latest"
	nonSignedImage := "ghcr.io/inspektor-gadget/gadget/unsigned:francis-signature-unit-tests"

	goodPublicKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEn6u8dLv8gnPGFEoAeeRXZ9r1QUqu
vxvpnBNH+Gwent1O0IisyCeEYEeGAOVcmqCLFywoF62CUMZIex/Xw56nfw==
-----END PUBLIC KEY-----
`
	wrongPublicKey := `
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIur1/9dgnL6gwRsXRoE5tgpiZX0V
wE3h/OMa2IqglFFvk8Qh1EX9zr5aASFdRcTKScjrU7uS1y6Z1z3NQe2P+g==
-----END PUBLIC KEY-----
`

	tests := map[string]testDefinition{
		"good_public_key_with_legacy_signed_image": {
			opts: VerifierOptions{
				PublicKeys: []string{goodPublicKey},
			},
			image: legacySignedImage,
		},
		"good_public_key_with_oci11_signed_image": {
			opts: VerifierOptions{
				PublicKeys: []string{goodPublicKey},
			},
			image: oci11SignedImage,
		},
		"good_public_key_with_bundle_signed_image": {
			opts: VerifierOptions{
				PublicKeys: []string{goodPublicKey},
			},
			image: bundleSignedImage,
		},
		"wrong_public_key_with_signed_image": {
			opts: VerifierOptions{
				PublicKeys: []string{wrongPublicKey},
			},
			image:     legacySignedImage,
			shouldErr: true,
		},
		"public_key_with_unsigned_image": {
			opts: VerifierOptions{
				PublicKeys: []string{goodPublicKey},
			},
			image:     nonSignedImage,
			shouldErr: true,
		},
		"several_public_keys_with_signed_image": {
			opts: VerifierOptions{
				PublicKeys: []string{
					wrongPublicKey,
					goodPublicKey,
				},
			},
			image: legacySignedImage,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, err := oci.New(filepath.Join("..", "..", "testdata", "oci-store"))
			require.NoError(t, err)

			ref, err := reference.ParseNormalizedNamed(test.image)
			require.NoError(t, err)

			ref = reference.TagNameOnly(ref)

			repo, err := remote.NewRepository(ref.Name())
			require.NoError(t, err)

			verifier, err := NewVerifier(test.opts)
			require.NoError(t, err)

			err = verifier.Verify(context.Background(), repo, store, ref)
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
