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
	"testing"

	"github.com/distribution/reference"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry/remote"
	"oras.land/oras-go/v2/registry/remote/auth"
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

func TestPullSigningInformation(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image     string
		shouldErr bool
	}

	tests := map[string]testDefinition{
		"cosign_signed_image": {
			// v0.43.0
			image: "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:7ecd35cc935edb56c7beb1077e4ca1aabdd1d4e4429b0df027398534d6da9fe6",
		},
		"non_signed_image": {
			// v0.25.0
			image:     "ghcr.io/inspektor-gadget/gadget/trace_open@sha256:a5de3655d6c7640eb6d43f7d9d7182b233ac86aedddfe6c132cba6b876264d97",
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

			err = DefaultSignaturePuller.PullSigningInformation(ctx, repo, store, desc.Digest.String())
			if test.shouldErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
		})
	}
}
