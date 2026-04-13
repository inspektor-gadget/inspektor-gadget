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

package helpers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
)

func TestFindReferrerTagFallsBackToManifestInspection(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"bundle":   BundleV03MediaType,
		"cosign":   CosignSignatureMediaType,
		"notation": NotationSignatureMediatype,
	}

	for name, artifactType := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			ctx := context.Background()
			store, imageDesc, referrerDescs := createImageWithReferrers(t, ctx, artifactType, 2)

			tags, err := findReferrerTags(ctx, &ghcrLikeStore{Store: store}, imageDesc.Digest.String(), artifactType)
			require.NoError(t, err)
			require.Len(t, tags, len(referrerDescs))

			expected := make(map[string]struct{}, len(referrerDescs))
			for _, referrerDesc := range referrerDescs {
				expected[referrerDesc.Digest.String()] = struct{}{}
			}

			for _, tag := range tags {
				_, ok := expected[tag]
				require.True(t, ok)
			}

			signingInfoTag, err := findReferrerTag(ctx, &ghcrLikeStore{Store: store}, imageDesc.Digest.String(), artifactType)
			require.NoError(t, err)
			_, ok := expected[signingInfoTag]
			require.True(t, ok)
		})
	}
}

type ghcrLikeStore struct {
	*oci.Store
}

func (s *ghcrLikeStore) Referrers(ctx context.Context, desc ocispec.Descriptor, artifactType string, fn func(referrers []ocispec.Descriptor) error) error {
	referrers, err := registry.Referrers(ctx, s.Store, desc, "")
	if err != nil {
		return err
	}

	if artifactType != "" {
		return fn(nil)
	}

	referrers = append([]ocispec.Descriptor{{
		MediaType: ocispec.MediaTypeImageManifest,
		Digest:    digest.Digest("sha256:1111111111111111111111111111111111111111111111111111111111111111"),
		Size:      123,
	}}, referrers...)

	for i := range referrers {
		referrers[i].ArtifactType = ocispec.DescriptorEmptyJSON.MediaType
	}

	return fn(referrers)
}

func createImageWithReferrers(t *testing.T, ctx context.Context, artifactType string, count int) (*oci.Store, ocispec.Descriptor, []ocispec.Descriptor) {
	t.Helper()

	store, err := oci.New(t.TempDir())
	require.NoError(t, err)

	configDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageConfig, []byte(`{"architecture":"amd64","os":"linux"}`))
	layerDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageLayer, []byte("fake-layer"))

	imageManifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	imageManifest.SchemaVersion = 2
	imageManifestBytes, err := json.Marshal(imageManifest)
	require.NoError(t, err)

	imageDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageManifest, imageManifestBytes)
	require.NoError(t, store.Tag(ctx, imageDesc, "ghcr.io/example/test:latest"))

	pushBlob(t, ctx, store, ocispec.DescriptorEmptyJSON.MediaType, []byte(`{}`))

	referrerDescs := make([]ocispec.Descriptor, 0, count)
	for i := 0; i < count; i++ {
		referrerManifest := ocispec.Manifest{
			MediaType:    ocispec.MediaTypeImageManifest,
			ArtifactType: artifactType,
			Subject:      &imageDesc,
			Config:       ocispec.DescriptorEmptyJSON,
			Layers: []ocispec.Descriptor{
				pushBlob(t, ctx, store, artifactType, []byte(fmt.Sprintf("signature-%d", i))),
			},
		}
		referrerManifest.SchemaVersion = 2
		referrerManifestBytes, err := json.Marshal(referrerManifest)
		require.NoError(t, err)

		referrerDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageManifest, referrerManifestBytes)
		referrerDescs = append(referrerDescs, referrerDesc)
	}

	require.NoError(t, store.SaveIndex())

	return store, imageDesc, referrerDescs
}

func pushBlob(t *testing.T, ctx context.Context, store *oci.Store, mediaType string, data []byte) ocispec.Descriptor {
	t.Helper()

	desc := ocispec.Descriptor{
		MediaType: mediaType,
		Digest:    digest.FromBytes(data),
		Size:      int64(len(data)),
	}

	err := store.Push(ctx, desc, bytes.NewReader(data))
	if err != nil {
		exists, checkErr := store.Exists(ctx, desc)
		if checkErr != nil || !exists {
			t.Fatalf("pushing blob: %v", err)
		}
	}

	return desc
}
