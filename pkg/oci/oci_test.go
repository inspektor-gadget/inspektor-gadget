// Copyright 2023 The Inspektor Gadget authors
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

package oci

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"
)

func TestExtendedCopyPreservesReferrers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	// 1. Create a source OCI store with a tagged image + untagged referrer
	srcDir := t.TempDir()
	srcStore, err := oci.New(srcDir)
	require.NoError(t, err)

	// Push a minimal image: config + layer + manifest
	configBlob := []byte(`{"architecture":"amd64","os":"linux"}`)
	configDesc := pushBlob(t, ctx, srcStore, ocispec.MediaTypeImageConfig, configBlob)

	layerBlob := []byte("fake-layer-data")
	layerDesc := pushBlob(t, ctx, srcStore, ocispec.MediaTypeImageLayer, layerBlob)

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifest.SchemaVersion = 2
	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)
	manifestDesc := pushBlob(t, ctx, srcStore, ocispec.MediaTypeImageManifest, manifestBytes)

	imageRef := "test.example.com/image:latest"
	err = srcStore.Tag(ctx, manifestDesc, imageRef)
	require.NoError(t, err)

	// Push an untagged referrer manifest (notation-like signature)
	sigBlob := []byte("fake-notation-signature")
	sigLayerDesc := pushBlob(t, ctx, srcStore, "application/octet-stream", sigBlob)

	sigManifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: "application/vnd.cncf.notary.signature",
		Subject:      &manifestDesc,
		Config: ocispec.Descriptor{
			MediaType: "application/vnd.oci.empty.v1+json",
			Digest:    ocispec.DescriptorEmptyJSON.Digest,
			Size:      ocispec.DescriptorEmptyJSON.Size,
		},
		Layers: []ocispec.Descriptor{sigLayerDesc},
	}
	sigManifest.SchemaVersion = 2

	// Push the empty config for the signature manifest
	emptyJSON := []byte(`{}`)
	pushBlob(t, ctx, srcStore, "application/vnd.oci.empty.v1+json", emptyJSON)

	sigManifestBytes, err := json.Marshal(sigManifest)
	require.NoError(t, err)
	sigManifestDesc := pushBlob(t, ctx, srcStore, ocispec.MediaTypeImageManifest, sigManifestBytes)
	// Do NOT tag the signature manifest — it's an untagged referrer

	err = srcStore.SaveIndex()
	require.NoError(t, err)

	// Verify the referrer is discoverable in the source
	referrers, err := registry.Referrers(ctx, srcStore, manifestDesc, "application/vnd.cncf.notary.signature")
	require.NoError(t, err)
	require.Len(t, referrers, 1, "source store should have 1 referrer")

	// 2. Test: oras.Copy does NOT copy the referrer (demonstrates the bug)
	dstCopyDir := t.TempDir()
	dstCopy, err := oci.New(dstCopyDir)
	require.NoError(t, err)

	_, err = oras.Copy(ctx, srcStore, imageRef, dstCopy, imageRef, oras.DefaultCopyOptions)
	require.NoError(t, err)

	exists, err := dstCopy.Exists(ctx, sigManifestDesc)
	require.NoError(t, err)
	assert.False(t, exists, "oras.Copy should NOT copy untagged referrer manifests (this is the bug)")

	// 3. Test: oras.ExtendedCopy DOES copy the referrer (the fix)
	dstExtDir := t.TempDir()
	dstExt, err := oci.New(dstExtDir)
	require.NoError(t, err)

	_, err = oras.ExtendedCopy(ctx, srcStore, imageRef, dstExt, imageRef, oras.DefaultExtendedCopyOptions)
	require.NoError(t, err)

	exists, err = dstExt.Exists(ctx, sigManifestDesc)
	require.NoError(t, err)
	assert.True(t, exists, "oras.ExtendedCopy should copy untagged referrer manifests")

	// Verify the referrer relationship is preserved in the destination
	dstReferrers, err := registry.Referrers(ctx, dstExt, manifestDesc, "application/vnd.cncf.notary.signature")
	require.NoError(t, err)
	require.Len(t, dstReferrers, 1, "destination store should have 1 referrer after ExtendedCopy")
	assert.Equal(t, sigManifestDesc.Digest, dstReferrers[0].Digest)
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
		// Blob may already exist (e.g., empty JSON config)
		existsErr, checkErr := store.Exists(ctx, desc)
		if checkErr != nil || !existsErr {
			t.Fatalf("pushing blob: %v", err)
		}
	}
	return desc
}

func TestSplitIGDomain(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		name              string
		expectedDomain    string
		expectedRemainder string
	}

	tests := map[string]testDefinition{
		"no_domain_and_remainder": {
			name:              "trace_exec",
			expectedDomain:    DefaultDomain,
			expectedRemainder: officialRepoPrefix + "trace_exec",
		},
		"no_domain_and_remainder_with_tag": {
			name:              "trace_exec:v0.42.0",
			expectedDomain:    DefaultDomain,
			expectedRemainder: officialRepoPrefix + "trace_exec:v0.42.0",
		},
		"no_domain": {
			name:              "xyz/gadget/trace_exec",
			expectedDomain:    DefaultDomain,
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full": {
			name:              "foobar.baz/xyz/gadget/trace_exec",
			expectedDomain:    "foobar.baz",
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full_with_port": {
			name:              "foobar.baz:443/xyz/gadget/trace_exec",
			expectedDomain:    "foobar.baz:443",
			expectedRemainder: "xyz/gadget/trace_exec",
		},
		"full_with_port_with_tag": {
			name:              "foobar.baz:443/xyz/gadget/trace_exec:v0.42.0",
			expectedDomain:    "foobar.baz:443",
			expectedRemainder: "xyz/gadget/trace_exec:v0.42.0",
		},
		"localhost": {
			name:              "localhost/trace_exec",
			expectedDomain:    "localhost",
			expectedRemainder: "trace_exec",
		},
		"localhost_with_long_remainder": {
			name:              "localhost/a/b/c/e/d/g/r/trace_exec",
			expectedDomain:    "localhost",
			expectedRemainder: "a/b/c/e/d/g/r/trace_exec",
		},
		"localhost_with_port": {
			name:              "localhost:5000/trace_exec",
			expectedDomain:    "localhost:5000",
			expectedRemainder: "trace_exec",
		},
		"localhost_with_port_with_tag": {
			name:              "localhost:5000/trace_exec:v1.0.3",
			expectedDomain:    "localhost:5000",
			expectedRemainder: "trace_exec:v1.0.3",
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			actualDomain, actualRemainder := SplitIGDomain(test.name)
			assert.Equal(t, test.expectedDomain, actualDomain)
			assert.Equal(t, test.expectedRemainder, actualRemainder)
		})
	}
}

func TestNormalizeImage(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image         string
		imageExpected string
		err           bool
	}

	tests := map[string]testDefinition{
		"empty": {
			image: "",
			err:   true,
		},
		"badtag": {
			image: "inspektor-gadget/ig:~½¬",
			err:   true,
		},
		"image": {
			image:         "ig",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latest",
		},
		"image_and_tag": {
			image:         "ig:latest",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latest",
		},
		"image_and_tag_2": {
			image:         "ig:latestttt",
			imageExpected: "ghcr.io/inspektor-gadget/gadget/ig:latestttt",
		},
		"host_image_and_tag": {
			image:         "inspektor-gadget/ig:foobar",
			imageExpected: "ghcr.io/inspektor-gadget/ig:foobar",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:baz",
			err:   true,
		},
		"host_port_image_and_tag": {
			image:         "ghcr.io:443/inspektor-gadget/ig:baz",
			imageExpected: "ghcr.io:443/inspektor-gadget/ig:baz",
		},
		"schema_host_port_image_and_tag": {
			image: "https://ghcr.io:443/inspektor-gadget/ig:latest",
			err:   true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			imageRef, err := normalizeImageName(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.imageExpected, imageRef.String())
		})
	}
}

func TestGetHostString(t *testing.T) {
	t.Parallel()

	type testDefinition struct {
		image string
		host  string
		err   bool
	}

	tests := map[string]testDefinition{
		"empty": {
			image: "",
			err:   true,
		},
		"badtag": {
			image: "inspektor-gadget/ig:~½¬",
			err:   true,
		},
		"image": {
			image: "ig",
			host:  "",
		},
		"host": {
			image: "ghcr.io",
			host:  "",
		},
		"host_image_and_tag": {
			image: "inspektor-gadget/ig:latest",
			host:  "inspektor-gadget",
		},
		"schema_host_image_and_tag": {
			image: "https://inspektor-gadget/ig:latest",
			err:   true,
		},
		"host_port_image_and_tag": {
			image: "ghcr.io:443/inspektor-gadget/ig:latest",
			host:  "ghcr.io:443",
		},
		"schema_host_port_image_and_tag": {
			image: "https://ghcr.io:443/inspektor-gadget/ig:latest",
			err:   true,
		},
	}

	for name, test := range tests {
		test := test
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			host, err := getHostString(test.image)
			if test.err {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, test.host, host)
		})
	}
}
