// Copyright 2026 The Inspektor Gadget authors
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
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/stretchr/testify/require"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/registry"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/signature/helpers"
)

// pushImage pushes a minimal image manifest, whose config carries the given
// name so that each image gets a distinct digest, and returns its descriptor.
func pushImage(t *testing.T, ctx context.Context, store *oci.Store, name string) ocispec.Descriptor {
	t.Helper()

	configDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageConfig,
		[]byte(`{"architecture":"amd64","os":"linux","name":"`+name+`"}`))
	layerDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageLayer, []byte("layer-of-"+name))

	manifest := ocispec.Manifest{
		MediaType: ocispec.MediaTypeImageManifest,
		Config:    configDesc,
		Layers:    []ocispec.Descriptor{layerDesc},
	}
	manifest.SchemaVersion = 2

	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	return pushBlob(t, ctx, store, ocispec.MediaTypeImageManifest, manifestBytes)
}

// indexManifests returns the manifest list of the store's index.json, as it is
// on disk. It is what oci.New() has to parse on every open, and hence what
// pruning is meant to keep small.
func indexManifests(t *testing.T, storePath string) []ocispec.Descriptor {
	t.Helper()

	index, err := readIndexFile(storePath + "/index.json")
	require.NoError(t, err)

	return index.Manifests
}

func digestsOf(descs []ocispec.Descriptor) []string {
	digests := make([]string, 0, len(descs))
	for _, desc := range descs {
		digests = append(digests, desc.Digest.String())
	}
	return digests
}

// A superseded image, left untagged in the index by a newer pull of the same
// tag, is unreachable and is what makes index.json grow without bound.
func TestPruneIndexManifestsDropsUntaggedUnreachableManifest(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	oldDesc := pushImage(t, ctx, store, "old")
	newDesc := pushImage(t, ctx, store, "new")

	// Both were pushed, so both are in the index, but only the newer one
	// keeps the tag.
	require.NoError(t, store.Tag(ctx, newDesc, "example.com/gadget:latest"))
	require.NoError(t, store.SaveIndex())

	manifests := indexManifests(t, storePath)
	require.ElementsMatch(t, digestsOf(manifests), digestsOf([]ocispec.Descriptor{oldDesc, newDesc}),
		"both manifests should start out in the index")

	kept, removed, err := pruneIndexManifests(ctx, store, manifests)
	require.NoError(t, err)

	require.Equal(t, digestsOf([]ocispec.Descriptor{newDesc}), digestsOf(kept))
	require.Equal(t, digestsOf([]ocispec.Descriptor{oldDesc}), digestsOf(removed))
}

// pushReferrer pushes an untagged referrer manifest (as cosign bundles and
// notation signatures are stored) pointing at subject, and returns its
// descriptor.
func pushReferrer(t *testing.T, ctx context.Context, store *oci.Store, artifactType string, subject ocispec.Descriptor) ocispec.Descriptor {
	t.Helper()

	pushBlob(t, ctx, store, ocispec.MediaTypeEmptyJSON, []byte(`{}`))
	layerDesc := pushBlob(t, ctx, store, "application/octet-stream",
		[]byte("signature-of-"+subject.Digest.String()))

	manifest := ocispec.Manifest{
		MediaType:    ocispec.MediaTypeImageManifest,
		ArtifactType: artifactType,
		Subject:      &subject,
		Config: ocispec.Descriptor{
			MediaType: ocispec.MediaTypeEmptyJSON,
			Digest:    ocispec.DescriptorEmptyJSON.Digest,
			Size:      ocispec.DescriptorEmptyJSON.Size,
		},
		Layers: []ocispec.Descriptor{layerDesc},
	}
	manifest.SchemaVersion = 2

	manifestBytes, err := json.Marshal(manifest)
	require.NoError(t, err)

	return pushBlob(t, ctx, store, ocispec.MediaTypeImageManifest, manifestBytes)
}

// Signatures are stored as untagged referrer manifests, and
// pkg/signature/helpers finds them with registry.Referrers() on the local
// store, which relies on their index.json entry. Pruning them would silently
// break the verification of an already pulled image.
func TestPruneIndexManifestsKeepsUntaggedReferrerOfKeptImage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	imageDesc := pushImage(t, ctx, store, "signed")
	require.NoError(t, store.Tag(ctx, imageDesc, "example.com/gadget:latest"))

	sigDesc := pushReferrer(t, ctx, store, helpers.NotationSignatureMediatype, imageDesc)
	require.NoError(t, store.SaveIndex())

	kept, removed, err := pruneIndexManifests(ctx, store, indexManifests(t, storePath))
	require.NoError(t, err)

	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{imageDesc, sigDesc}), digestsOf(kept),
		"the untagged signature of a kept image must be kept")
	require.Empty(t, digestsOf(removed))
}

// A bundle can refer to a signature that refers to the image, so keeping
// referrers has to be transitive.
func TestPruneIndexManifestsKeepsChainedReferrers(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	imageDesc := pushImage(t, ctx, store, "signed")
	require.NoError(t, store.Tag(ctx, imageDesc, "example.com/gadget:latest"))

	sigDesc := pushReferrer(t, ctx, store, helpers.NotationSignatureMediatype, imageDesc)
	bundleDesc := pushReferrer(t, ctx, store, helpers.BundleV03MediaType, sigDesc)
	require.NoError(t, store.SaveIndex())

	kept, removed, err := pruneIndexManifests(ctx, store, indexManifests(t, storePath))
	require.NoError(t, err)

	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{imageDesc, sigDesc, bundleDesc}), digestsOf(kept))
	require.Empty(t, digestsOf(removed))
}

// A referrer left behind by "ig image remove" refers to a manifest that is no
// longer kept. Such an entry is garbage, and walking its subject chain must
// terminate: oras' own Store.GC() spins forever here, because the subject
// variable in the referrer loop of its gcIndex() is shadowed and never
// advances.
func TestPruneIndexManifestsRemovesOrphanReferrer(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	// The image is pushed but never tagged, as if its tag had been removed.
	imageDesc := pushImage(t, ctx, store, "removed")
	sigDesc := pushReferrer(t, ctx, store, helpers.NotationSignatureMediatype, imageDesc)
	require.NoError(t, store.SaveIndex())

	done := make(chan struct{})
	var kept, removed []ocispec.Descriptor
	go func() {
		defer close(done)
		kept, removed, err = pruneIndexManifests(ctx, store, indexManifests(t, storePath))
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("pruneIndexManifests did not terminate on an orphan referrer")
	}

	require.NoError(t, err)
	require.Empty(t, digestsOf(kept))
	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{imageDesc, sigDesc}), digestsOf(removed))
}

// Gadget images are image indexes, and oras records every per-host manifest
// they contain in index.json as an untagged entry. Those are the bulk of the
// index, and dropping them is safe: they stay reachable through the index
// blob, and Store.Resolve() falls back to resolving a digest from the blobs.
func TestPruneIndexManifestsDropsPerHostManifestsOfKeptIndex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	amd64Desc := pushImage(t, ctx, store, "amd64")
	arm64Desc := pushImage(t, ctx, store, "arm64")

	index := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{amd64Desc, arm64Desc},
	}
	index.SchemaVersion = 2
	indexBytes, err := json.Marshal(index)
	require.NoError(t, err)

	indexDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageIndex, indexBytes)
	require.NoError(t, store.Tag(ctx, indexDesc, "example.com/gadget:latest"))
	require.NoError(t, store.SaveIndex())

	kept, removed, err := pruneIndexManifests(ctx, store, indexManifests(t, storePath))
	require.NoError(t, err)

	require.Equal(t, digestsOf([]ocispec.Descriptor{indexDesc}), digestsOf(kept))
	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{amd64Desc, arm64Desc}), digestsOf(removed))
}

// Pruning has to leave a store the next ig run can use: the tag resolves, the
// per-host manifest of the kept index is still fetchable even though its index
// entry is gone, and the signature is still discoverable as a referrer.
func TestPruneStoreIndexKeepsStoreUsable(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	perHostDesc := pushImage(t, ctx, store, "amd64")
	index := ocispec.Index{
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: []ocispec.Descriptor{perHostDesc},
	}
	index.SchemaVersion = 2
	indexBytes, err := json.Marshal(index)
	require.NoError(t, err)
	indexDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageIndex, indexBytes)

	const ref = "example.com/gadget:latest"
	require.NoError(t, store.Tag(ctx, indexDesc, ref))
	sigDesc := pushReferrer(t, ctx, store, helpers.NotationSignatureMediatype, indexDesc)

	// A superseded version of the same gadget, left untagged by a newer pull.
	supersededDesc := pushImage(t, ctx, store, "superseded")
	require.NoError(t, store.SaveIndex())

	result, err := pruneStoreIndex(ctx, storePath, store, false)
	require.NoError(t, err)
	require.Equal(t, 2, result.IndexEntriesRemoved, "the superseded and per-host manifests")

	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{indexDesc, sigDesc}),
		digestsOf(indexManifests(t, storePath)))

	// Reopen the store the way the next ig run would.
	reopened, err := oci.New(storePath)
	require.NoError(t, err)

	resolved, err := reopened.Resolve(ctx, ref)
	require.NoError(t, err)
	require.Equal(t, indexDesc.Digest, resolved.Digest)

	_, err = reopened.Resolve(ctx, perHostDesc.Digest.String())
	require.NoError(t, err, "a per-host manifest must stay resolvable by digest")

	referrers, err := registry.Referrers(ctx, reopened, indexDesc, helpers.NotationSignatureMediatype)
	require.NoError(t, err)
	require.Len(t, referrers, 1, "the signature must stay discoverable")

	_, err = reopened.Resolve(ctx, supersededDesc.Digest.String())
	require.NoError(t, err, "the blob of a pruned manifest is not deleted without pruneBlobs")
}

func blobPath(storePath string, desc ocispec.Descriptor) string {
	return filepath.Join(storePath, ocispec.ImageBlobsDir,
		desc.Digest.Algorithm().String(), desc.Digest.Encoded())
}

// Reclaiming disk is only done by the explicit "ig image prune", and it must
// delete exactly the blobs nothing kept refers to.
func TestPruneStoreIndexWithBlobsRemovesOnlyUnreachableBlobs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, store, "kept")
	require.NoError(t, store.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	sigDesc := pushReferrer(t, ctx, store, helpers.NotationSignatureMediatype, keptDesc)

	supersededDesc := pushImage(t, ctx, store, "superseded")
	require.NoError(t, store.SaveIndex())

	// The blobs of the superseded image: its manifest, config and layer.
	supersededBlobs := []ocispec.Descriptor{supersededDesc}
	supersededSuccessors, err := content.Successors(ctx, store, supersededDesc)
	require.NoError(t, err)
	supersededBlobs = append(supersededBlobs, supersededSuccessors...)
	require.Len(t, supersededBlobs, 3)

	var wantFreed int64
	for _, desc := range supersededBlobs {
		wantFreed += desc.Size
	}

	result, err := pruneStoreIndex(ctx, storePath, store, true)
	require.NoError(t, err)
	require.Equal(t, len(supersededBlobs), result.BlobsRemoved)
	require.Equal(t, wantFreed, result.BytesFreed)

	for _, desc := range supersededBlobs {
		require.NoFileExists(t, blobPath(storePath, desc))
	}

	// Everything the kept image and its signature need must survive.
	for _, root := range []ocispec.Descriptor{keptDesc, sigDesc} {
		require.FileExists(t, blobPath(storePath, root))

		successors, err := content.Successors(ctx, store, root)
		require.NoError(t, err)
		for _, desc := range successors {
			require.FileExists(t, blobPath(storePath, desc))
		}
	}
}

// Another ig process can rewrite index.json between the moment the store was
// opened and the moment pruning saves it. Pruning must then behave like every
// other write in this package and ask to be retried, rather than overwrite
// what the other process wrote.
func TestPruneWithLockRetriesWhenIndexChangedConcurrently(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, ociStore.Store, "kept")
	require.NoError(t, ociStore.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	pushImage(t, ctx, ociStore.Store, "superseded")
	require.NoError(t, ociStore.saveIndexWithLock())

	// Simulate another process pulling an image in the meantime.
	other, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)
	otherDesc := pushImage(t, ctx, other.Store, "pulled-by-another-process")
	require.NoError(t, other.Tag(ctx, otherDesc, "example.com/other:latest"))
	require.NoError(t, other.saveIndexWithLock())

	before := indexManifests(t, storePath)

	_, err = ociStore.pruneWithLock(ctx, false)
	require.ErrorIs(t, err, errRetry)
	require.ElementsMatch(t, digestsOf(before), digestsOf(indexManifests(t, storePath)),
		"a stale store must not rewrite the index")
}

// The public entry point retries on a concurrent index change, the way every
// other write in this package does, so a busy store still gets pruned.
func TestPruneStoreRetriesAndPrunes(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, ociStore.Store, "kept")
	require.NoError(t, ociStore.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	supersededDesc := pushImage(t, ctx, ociStore.Store, "superseded")
	require.NoError(t, ociStore.saveIndexWithLock())

	result, err := pruneStore(ctx, storePath, false)
	require.NoError(t, err)
	require.Equal(t, 1, result.IndexEntriesRemoved)

	require.Equal(t, digestsOf([]ocispec.Descriptor{keptDesc}), digestsOf(indexManifests(t, storePath)))
	require.NotContains(t, digestsOf(indexManifests(t, storePath)), supersededDesc.Digest.String())

	// Pruning an already pruned store is a no-op.
	result, err = pruneStore(ctx, storePath, false)
	require.NoError(t, err)
	require.Zero(t, result.IndexEntriesRemoved)
}

// What the pull and build paths use: the new manifests are saved, then the
// entries nothing refers to are dropped, without touching any blob.
func TestSaveIndexAndPruneWithLockDropsUnreferencedEntries(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, ociStore.Store, "kept")
	require.NoError(t, ociStore.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	supersededDesc := pushImage(t, ctx, ociStore.Store, "superseded")

	require.NoError(t, ociStore.saveIndexAndPruneWithLock(ctx))

	require.Equal(t, digestsOf([]ocispec.Descriptor{keptDesc}), digestsOf(indexManifests(t, storePath)))
	require.FileExists(t, blobPath(storePath, supersededDesc),
		"the pull and build paths must not delete blobs")
}

// An image pulled by digest is referenced by "<name>@<digest>", which oras
// records as a reference and not as an untagged manifest. Pruning must keep
// it, and with it the signature that refers to it.
func TestSaveIndexAndPruneWithLockKeepsDigestPulledImage(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	imageDesc := pushImage(t, ctx, ociStore.Store, "pulled-by-digest")
	ref := "example.com/gadget@" + imageDesc.Digest.String()
	require.NoError(t, ociStore.Tag(ctx, imageDesc, ref))
	sigDesc := pushReferrer(t, ctx, ociStore.Store, helpers.NotationSignatureMediatype, imageDesc)

	require.NoError(t, ociStore.saveIndexAndPruneWithLock(ctx))

	require.ElementsMatch(t, digestsOf([]ocispec.Descriptor{imageDesc, sigDesc}),
		digestsOf(indexManifests(t, storePath)))
}

// With --oci-store-user as root the store belongs to the user and is opened
// read only, so running a gadget must not try to prune it.
func TestSaveIndexAndPruneWithLockSkipsReadOnlyStore(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, ociStore.Store, "kept")
	require.NoError(t, ociStore.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	supersededDesc := pushImage(t, ctx, ociStore.Store, "superseded")
	require.NoError(t, ociStore.saveIndexWithLock())

	ociStore.readOnly = true
	require.NoError(t, ociStore.saveIndexAndPruneWithLock(ctx))

	require.Contains(t, digestsOf(indexManifests(t, storePath)), supersededDesc.Digest.String())
}

// A pull interrupted after its blobs were written but before the index was
// saved leaves blobs no index entry refers to. Reclaiming them is the point of
// "ig image prune", so it must not be skipped just because the index itself
// has nothing to drop.
func TestPruneStoreIndexRemovesOrphanBlobsOfCleanIndex(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, store, "kept")
	require.NoError(t, store.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	require.NoError(t, store.SaveIndex())

	// A blob left behind by an interrupted pull: written, never indexed.
	orphan := []byte("blob-of-an-interrupted-pull")
	orphanDesc := pushBlob(t, ctx, store, ocispec.MediaTypeImageLayer, orphan)

	result, err := pruneStoreIndex(ctx, storePath, store, true)
	require.NoError(t, err)
	require.Zero(t, result.IndexEntriesRemoved)
	require.Equal(t, 1, result.BlobsRemoved)
	require.Equal(t, int64(len(orphan)), result.BytesFreed)

	require.NoFileExists(t, blobPath(storePath, orphanDesc))
	require.FileExists(t, blobPath(storePath, keptDesc))
}

// A long-lived store can list a manifest whose blob is gone, left by an
// interrupted operation or by the Store.GC() that "ig image remove" used to
// run. Deciding whether such an entry is a referrer is impossible, but it is
// garbage either way, so pruning drops it instead of failing: that is what the
// GC() call it replaces did with errdef.ErrNotFound.
func TestPruneIndexManifestsDropsEntryWithMissingBlob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	store, err := oci.New(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, store, "kept")
	require.NoError(t, store.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	danglingDesc := pushImage(t, ctx, store, "dangling")
	require.NoError(t, store.SaveIndex())

	require.NoError(t, os.Remove(blobPath(storePath, danglingDesc)))

	kept, removed, err := pruneIndexManifests(ctx, store, indexManifests(t, storePath))
	require.NoError(t, err)
	require.Equal(t, digestsOf([]ocispec.Descriptor{keptDesc}), digestsOf(kept))
	require.Equal(t, digestsOf([]ocispec.Descriptor{danglingDesc}), digestsOf(removed))
}

// The same store must not make "ig image remove" fail after the removal has
// already been committed.
func TestPruneWithLockSucceedsOnStoreWithMissingBlob(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	storePath := t.TempDir()
	ociStore, err := newLocalOciStoreAt(storePath)
	require.NoError(t, err)

	keptDesc := pushImage(t, ctx, ociStore.Store, "kept")
	require.NoError(t, ociStore.Tag(ctx, keptDesc, "example.com/gadget:latest"))
	danglingDesc := pushImage(t, ctx, ociStore.Store, "dangling")
	require.NoError(t, ociStore.saveIndexWithLock())

	require.NoError(t, os.Remove(blobPath(storePath, danglingDesc)))

	result, err := ociStore.pruneWithLock(ctx, true)
	require.NoError(t, err)
	require.Equal(t, 1, result.IndexEntriesRemoved)
}
