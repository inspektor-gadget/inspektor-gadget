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
	"testing"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/resources"
)

func createTestPrerequisities(t *testing.T, image string) (oras.Target, *remote.Repository, reference.Named) {
	store, err := oci.New(t.TempDir())
	require.NoError(t, err)

	ref, err := reference.ParseNormalizedNamed(image)
	require.NoError(t, err)

	ref = reference.TagNameOnly(ref)

	repo, err := remote.NewRepository(ref.Name())
	require.NoError(t, err)

	repo.Client = &auth.Client{
		Credential: auth.StaticCredential(reference.Domain(ref), auth.EmptyCredential),
	}

	return store, repo, ref
}

func TestVerify(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		opts      VerifyOptions
		image     string
		shouldErr bool
	}

	// v0.43.0
	signedImage := "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:7ecd35cc935edb56c7beb1077e4ca1aabdd1d4e4429b0df027398534d6da9fe6"

	// v0.25.0
	nonSignedImage := "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:a5de3655d6c7640eb6d43f7d9d7182b233ac86aedddfe6c132cba6b876264d97"

	tests := map[string]testDefinition{
		"no public key": {
			image:     signedImage,
			shouldErr: true,
		},
		"good public key with signed gadget": {
			opts: VerifyOptions{
				CosignVerifyOptions: CosignVerifyOptions{
					PublicKeys: []string{resources.InspektorGadgetPublicKey},
				},
			},
			image: signedImage,
		},
		"malformed public key with signed gadget": {
			opts: VerifyOptions{
				CosignVerifyOptions: CosignVerifyOptions{
					PublicKeys: []string{"foobar"},
				},
			},
			image:     signedImage,
			shouldErr: true,
		},
		"wrong public key with signed gadget": {
			opts: VerifyOptions{
				CosignVerifyOptions: CosignVerifyOptions{
					PublicKeys: []string{
						`
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEIur1/9dgnL6gwRsXRoE5tgpiZX0V
wE3h/OMa2IqglFFvk8Qh1EX9zr5aASFdRcTKScjrU7uS1y6Z1z3NQe2P+g==
-----END PUBLIC KEY-----
`,
					},
				},
			},
			image:     signedImage,
			shouldErr: true,
		},
		"public key with unsigned gadget": {
			opts: VerifyOptions{
				CosignVerifyOptions: CosignVerifyOptions{
					PublicKeys: []string{resources.InspektorGadgetPublicKey},
				},
			},
			image:     nonSignedImage,
			shouldErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			store, repo, ref := createTestPrerequisities(t, test.image)

			// Pull the image.
			_, err := oras.Copy(context.Background(), repo, ref.String(), store, ref.String(), oras.DefaultCopyOptions)
			require.NoError(t, err)

			err = Verify(context.Background(), repo, store, ref, test.opts)
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestPullSigningInformation(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image     string
		shouldErr bool
	}

	// v0.43.0
	signedImage := "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:7ecd35cc935edb56c7beb1077e4ca1aabdd1d4e4429b0df027398534d6da9fe6"

	// v0.25.0
	nonSignedImage := "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:a5de3655d6c7640eb6d43f7d9d7182b233ac86aedddfe6c132cba6b876264d97"

	tests := map[string]testDefinition{
		"signed image": {
			image: signedImage,
		},
		"non signed image": {
			image:     nonSignedImage,
			shouldErr: true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()

			store, repo, ref := createTestPrerequisities(t, test.image)

			// Pull the image.
			desc, err := oras.Copy(context.Background(), repo, ref.String(), store, ref.String(), oras.DefaultCopyOptions)
			require.NoError(t, err)

			err = PullSigningInformation(ctx, repo, store, desc.Digest.String())
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}

func TestExportSigningInformation(t *testing.T) {
	t.Parallel()

	// v0.43.0
	signedImage := "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:7ecd35cc935edb56c7beb1077e4ca1aabdd1d4e4429b0df027398534d6da9fe6"

	destSignedImage := "ttl.sh/gadget/trace_open:unit-test-signing"

	ctx := context.Background()

	store, repo, ref := createTestPrerequisities(t, signedImage)
	destStore, _, destRef := createTestPrerequisities(t, destSignedImage)

	// Pull the image.
	desc, err := oras.Copy(context.Background(), repo, ref.String(), store, ref.String(), oras.DefaultCopyOptions)
	require.NoError(t, err)

	err = PullSigningInformation(ctx, repo, store, desc.Digest.String())
	require.NoError(t, err)

	// Push the image
	desc, err = oras.Copy(ctx, store, ref.String(), destStore, destRef.String(), oras.DefaultCopyOptions)
	require.NoError(t, err)

	err = ExportSigningInformation(ctx, store, destStore, desc)
	require.NoError(t, err)
}
