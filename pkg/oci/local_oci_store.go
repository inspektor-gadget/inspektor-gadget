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
	"os/user"
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

const userOciStoreSubDir = ".ig/oci-store"

var useUserOciStore bool

func SetUseUserOciStore(v bool) {
	useUserOciStore = v
}

func getOciStorePath() (string, error) {
	username := ""
	if os.Geteuid() == 0 {
		if useUserOciStore {
			// Running as root, with --oci-store-user.
			username = os.Getenv("SUDO_USER")
		} else {
			// Running as root, without --oci-store-user
			return rootOciStore, nil
		}
	} else {
		// Running as normal user.
		u, err := user.Current()
		if err != nil {
			return "", fmt.Errorf("getting current user: %w", err)
		}
		username = u.Username
	}

	return getUserOciStorePath(username)
}

func getUserOciStorePath(username string) (string, error) {
	u, err := user.Lookup(username)
	if err != nil {
		return "", fmt.Errorf("finding user %q: %w", username, err)
	}

	return filepath.Join(u.HomeDir, userOciStoreSubDir), nil
}

// newLocalOciStore returns a localOciStore that is safe when executed
// concurrently, even from different processes.
func newLocalOciStore() (*localOciStore, error) {
	ociStorePath, err := getOciStorePath()
	if err != nil {
		return nil, fmt.Errorf("getting OCI store path: %w", err)
	}

	if err := os.MkdirAll(ociStorePath, 0o700); err != nil {
		return nil, err
	}

	indexPath := path.Join(ociStorePath, "index.json")
	indexLock := flock.New(path.Join(ociStorePath, "index.json.lock"))

	// lock the file before reading the index below
	// RLock can't be used since we might create and init an empty index file in oci.New()
	indexLock.Lock()
	defer indexLock.Unlock()

	ociStore, err := oci.New(ociStorePath)
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
