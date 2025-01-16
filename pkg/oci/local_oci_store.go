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

package oci

import (
	"encoding/json"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"reflect"

	"github.com/gofrs/flock"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2/content/oci"
)

type localOciStore struct {
	*oci.Store

	indexPath  string
	oldIndex   *ocispec.Index
	indexFlock *flock.Flock
}

// newLocalOciStore returns a localOciStore that is safe when executed
// concurrently, even from different processes.
func newLocalOciStore() (*localOciStore, error) {
	if err := os.MkdirAll(filepath.Dir(defaultOciStore), 0o700); err != nil {
		return nil, err
	}

	indexPath := path.Join(defaultOciStore, "index.json")
	indexLock := flock.New(path.Join(defaultOciStore, "index.json.lock"))

	// lock the file before reading the index below
	indexLock.RLock()
	defer indexLock.Unlock()

	ociStore, err := oci.New(defaultOciStore)
	if err != nil {
		return nil, err
	}
	ociStore.AutoSaveIndex = false

	oldIndex, err := readIndexFile(indexPath)
	if err != nil {
		return nil, err
	}

	return &localOciStore{
		Store:      ociStore,
		indexPath:  indexPath,
		oldIndex:   oldIndex,
		indexFlock: indexLock,
	}, nil
}

func (o *localOciStore) saveIndexWithLock() error {
	o.indexFlock.Lock()
	defer o.indexFlock.Unlock()

	currentIndex, err := readIndexFile(o.indexPath)
	if err != nil {
		return err
	}

	if !reflect.DeepEqual(currentIndex, o.oldIndex) {
		return errRetry
	}

	if err := o.SaveIndex(); err != nil {
		return fmt.Errorf("saving index: %w", err)
	}

	// Update the old index to the new one. Ideally we should get index from
	// oci.Store but it's not exposed, so read this from the index file instead.
	indexUpdated, err := readIndexFile(o.indexPath)
	if err != nil {
		return err
	}

	o.oldIndex = indexUpdated

	return nil
}

// readIndexFile reads index.json from the file system.
func readIndexFile(indexPath string) (*ocispec.Index, error) {
	indexFile, err := os.Open(indexPath)
	if err != nil {
		return nil, err
	}

	defer indexFile.Close()

	var index ocispec.Index
	if err := json.NewDecoder(indexFile).Decode(&index); err != nil {
		return nil, fmt.Errorf("decoding index file: %w", err)
	}

	return &index, nil
}
