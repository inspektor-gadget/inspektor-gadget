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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"

	log "github.com/sirupsen/logrus"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// pruneIndexManifests splits the manifest list of an index.json into the
// entries worth keeping and the ones that can be dropped.
//
// Kept are the tagged entries and, transitively, the untagged manifests
// referring to a kept one through their subject field. A signature can be
// stored either way: cosign tags it, while a bundle is found with
// registry.Referrers() in pkg/signature/helpers, which only knows the
// manifests listed in index.json.
//
// Dropped are the untagged entries nothing refers to. They are what makes
// index.json grow without bound, since oras records every pushed manifest in
// it and only ever removes the one an explicit "ig image remove" targets. The
// content they point at is not deleted: descendants of a kept manifest keep
// being resolvable by digest from the blobs.
func pruneIndexManifests(ctx context.Context, fetcher content.Fetcher, manifests []ocispec.Descriptor) (kept, removed []ocispec.Descriptor, err error) {
	keptDigests := make(map[digest.Digest]struct{}, len(manifests))
	var pending []ocispec.Descriptor

	for _, desc := range manifests {
		if desc.Annotations[ocispec.AnnotationRefName] != "" {
			kept = append(kept, desc)
			keptDigests[desc.Digest] = struct{}{}
			continue
		}

		pending = append(pending, desc)
	}

	// A referrer can itself be referred to, so keep going until a pass keeps
	// nothing new. Iterating to a fixpoint rather than walking each subject
	// chain also means a cycle, or a chain that never reaches a kept
	// manifest, cannot loop forever.
	for len(pending) > 0 {
		var stillPending []ocispec.Descriptor

		for _, desc := range pending {
			subject, err := manifestSubject(ctx, fetcher, desc)
			if err != nil {
				return nil, nil, fmt.Errorf("getting subject of %s: %w", desc.Digest, err)
			}

			if subject == nil {
				removed = append(removed, desc)
				continue
			}

			if _, ok := keptDigests[subject.Digest]; !ok {
				stillPending = append(stillPending, desc)
				continue
			}

			kept = append(kept, desc)
			keptDigests[desc.Digest] = struct{}{}
		}

		if len(stillPending) == len(pending) {
			// No progress: whatever is left refers to nothing that is kept.
			removed = append(removed, stillPending...)
			break
		}

		pending = stillPending
	}

	return kept, removed, nil
}

// manifestSubject returns the subject of a manifest or an image index, or nil
// when it has none, i.e. when it is not a referrer.
//
// A manifest whose blob is missing from the store is reported as having no
// subject: a long-lived store can list one, and it is garbage in any case, so
// pruning drops it rather than failing.
func manifestSubject(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) (*ocispec.Descriptor, error) {
	switch desc.MediaType {
	case ocispec.MediaTypeImageManifest, ocispec.MediaTypeImageIndex:
	default:
		return nil, nil
	}

	data, err := content.FetchAll(ctx, fetcher, desc)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) || errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}

	// Both ocispec.Manifest and ocispec.Index carry the field, so the
	// smallest struct holding it is enough for either media type.
	var manifest struct {
		Subject *ocispec.Descriptor `json:"subject,omitempty"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return nil, fmt.Errorf("unmarshalling manifest: %w", err)
	}

	return manifest.Subject, nil
}

// PruneResult reports what pruning removed.
type PruneResult struct {
	// IndexEntriesRemoved is the number of manifests dropped from index.json.
	// It is what makes opening the store faster, since oci.New() parses the
	// whole manifest graph listed there on every open.
	IndexEntriesRemoved int

	// BlobsRemoved and BytesFreed report the disk reclaimed by the blob
	// sweep, and stay zero when only the index was pruned.
	BlobsRemoved int
	BytesFreed   int64
}

// pruneStoreIndex rewrites the index.json of the store at storePath, keeping
// only the entries pruneIndexManifests() reports as worth keeping. Manifests
// are read through fetcher.
//
// The caller is responsible for the locking, and must not save the index from
// an oras store opened before the rewrite: its in-memory tag resolver still
// holds the dropped entries and would write them back.
func pruneStoreIndex(ctx context.Context, storePath string, fetcher content.Fetcher, pruneBlobs bool) (*PruneResult, error) {
	indexPath := filepath.Join(storePath, ocispec.ImageIndexFile)

	index, err := readIndexFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("reading index file: %w", err)
	}

	kept, removed, err := pruneIndexManifests(ctx, fetcher, index.Manifests)
	if err != nil {
		return nil, err
	}

	result := &PruneResult{IndexEntriesRemoved: len(removed)}

	if len(removed) > 0 {
		index.Manifests = kept
		if err := writeIndexFile(indexPath, index); err != nil {
			return nil, err
		}
	}

	if !pruneBlobs {
		return result, nil
	}

	if err := sweepBlobs(ctx, storePath, fetcher, kept, result); err != nil {
		return nil, fmt.Errorf("removing unreachable blobs: %w", err)
	}

	return result, nil
}

// sweepBlobs deletes the blobs that are not reachable from any of the kept
// manifests, and records in result what it freed.
//
// This is only done by an explicit "ig image prune": blobs are written before
// the index that references them is saved, and without holding the index lock,
// so a concurrently running ig could have blobs on disk that no index reports
// as reachable yet.
func sweepBlobs(ctx context.Context, storePath string, fetcher content.Fetcher, kept []ocispec.Descriptor, result *PruneResult) error {
	reachable, err := reachableDigests(ctx, fetcher, kept)
	if err != nil {
		return err
	}

	blobsPath := filepath.Join(storePath, ocispec.ImageBlobsDir)
	algDirs, err := os.ReadDir(blobsPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("reading %q: %w", blobsPath, err)
	}

	for _, algDir := range algDirs {
		if !algDir.IsDir() {
			continue
		}

		alg := digest.Algorithm(algDir.Name())
		algPath := filepath.Join(blobsPath, algDir.Name())

		entries, err := os.ReadDir(algPath)
		if err != nil {
			return fmt.Errorf("reading %q: %w", algPath, err)
		}

		for _, entry := range entries {
			if err := ctx.Err(); err != nil {
				return err
			}

			dgst := digest.NewDigestFromEncoded(alg, entry.Name())
			if err := dgst.Validate(); err != nil {
				// Not a blob, leave it alone.
				continue
			}

			if _, ok := reachable[dgst]; ok {
				continue
			}

			info, err := entry.Info()
			if err != nil {
				return fmt.Errorf("stating blob %s: %w", dgst, err)
			}

			if err := os.Remove(filepath.Join(algPath, entry.Name())); err != nil {
				return fmt.Errorf("removing blob %s: %w", dgst, err)
			}

			result.BlobsRemoved++
			result.BytesFreed += info.Size()
		}
	}

	return nil
}

// reachableDigests returns the digests of the given manifests and of
// everything they refer to, transitively.
func reachableDigests(ctx context.Context, fetcher content.Fetcher, roots []ocispec.Descriptor) (map[digest.Digest]struct{}, error) {
	reachable := make(map[digest.Digest]struct{}, len(roots))
	queue := slices.Clone(roots)

	for len(queue) > 0 {
		desc := queue[len(queue)-1]
		queue = queue[:len(queue)-1]

		if _, ok := reachable[desc.Digest]; ok {
			continue
		}
		reachable[desc.Digest] = struct{}{}

		successors, err := content.Successors(ctx, fetcher, desc)
		if err != nil {
			if errors.Is(err, errdef.ErrNotFound) {
				// A blob is already missing from the store: nothing to
				// walk, and nothing to delete either.
				continue
			}
			return nil, fmt.Errorf("getting successors of %s: %w", desc.Digest, err)
		}

		queue = append(queue, successors...)
	}

	return reachable, nil
}

// writeIndexFile writes index.json atomically, so that a store is never left
// with a partially written index if ig is interrupted.
func writeIndexFile(indexPath string, index *ocispec.Index) error {
	data, err := json.Marshal(index)
	if err != nil {
		return fmt.Errorf("marshalling index file: %w", err)
	}

	tmpPath := indexPath + ".tmp"
	if err := os.WriteFile(tmpPath, data, 0o600); err != nil {
		return fmt.Errorf("writing index file: %w", err)
	}

	if err := os.Rename(tmpPath, indexPath); err != nil {
		os.Remove(tmpPath)
		return fmt.Errorf("renaming index file: %w", err)
	}

	return nil
}

// pruneWithLock prunes the index of the store, and optionally its unreachable
// blobs, while holding the index lock.
//
// It returns errRetry when another process rewrote index.json since the store
// was opened, following the same protocol as saveIndexWithLock().
func (o *localOciStore) pruneWithLock(ctx context.Context, pruneBlobs bool) (*PruneResult, error) {
	if o.readOnly {
		return nil, errors.New("cannot prune a read-only store")
	}

	if err := o.indexFlock.Lock(); err != nil {
		return nil, fmt.Errorf("locking index file %q: %w", o.indexFlock.Path(), err)
	}
	defer o.indexFlock.Unlock()

	currentIndex, err := readIndexFile(o.indexPath)
	if err != nil {
		return nil, err
	}

	if !reflect.DeepEqual(currentIndex, o.oldIndex) {
		return nil, errRetry
	}

	result, err := pruneStoreIndex(ctx, o.storePath, o.Store, pruneBlobs)
	if err != nil {
		return nil, err
	}

	// Keep the snapshot in sync with what is now on disk, so that a later
	// save from this store does not see a spurious concurrent change. Note
	// that saving the index from this store would write the pruned entries
	// back, since its tag resolver still holds them.
	o.oldIndex, err = readIndexFile(o.indexPath)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// PruneGadgetImages removes from the local store the manifests no image refers
// to any more, and the blobs they were the only users of.
//
// Untagged manifests pile up in index.json as gadgets are pulled and built,
// and oci.New() parses the whole graph they describe on every open, so a store
// that is never pruned makes every ig invocation slower.
func PruneGadgetImages(ctx context.Context) (*PruneResult, error) {
	ociStorePath, err := getOciStorePath()
	if err != nil {
		return nil, fmt.Errorf("getting OCI store path: %w", err)
	}

	return pruneStore(ctx, ociStorePath, true)
}

// pruneStore prunes the store at storePath, retrying when a concurrent write
// to index.json makes the open store stale.
func pruneStore(ctx context.Context, storePath string, pruneBlobs bool) (*PruneResult, error) {
	var result *PruneResult

	err := retry("pruneStore", func() error {
		ociStore, err := newLocalOciStoreAt(storePath)
		if err != nil {
			return fmt.Errorf("getting oci store: %w", err)
		}

		result, err = ociStore.pruneWithLock(ctx, pruneBlobs)
		return err
	})

	return result, err
}

// saveIndexAndPruneWithLock saves the index and then drops the entries nothing
// refers to, which is what the paths adding manifests to the store use.
//
// Pruning failures are not fatal: whatever was just pulled or built is already
// saved, and an index that keeps a few stale entries only costs time.
func (o *localOciStore) saveIndexAndPruneWithLock(ctx context.Context) error {
	if err := o.saveIndexWithLock(); err != nil {
		return err
	}

	if o.readOnly {
		return nil
	}

	result, err := o.pruneWithLock(ctx, false)
	if err != nil {
		log.Debugf("pruning local oci store index: %v", err)
		return nil
	}

	if result.IndexEntriesRemoved > 0 {
		log.Debugf("pruned %d unreferenced manifests from the local oci store index",
			result.IndexEntriesRemoved)
	}

	return nil
}
