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

// userOciStoreSubDir is the path, relative to a user's home directory, of the
// per-user OCI store.
const userOciStoreSubDir = ".ig/oci-store"

// useUserOciStore indicates whether, when running as root, the OCI store of the
// user behind sudo should be used instead of the system-wide store. It has no
// effect when ig is not running as root, as the per-user store is always used
// in that case.
var useUserOciStore bool

// SetUseUserOciStore configures whether the OCI store of the user behind sudo
// should be used when running as root. See getLocalOciStorePath for details.
func SetUseUserOciStore(v bool) {
	useUserOciStore = v
}

// getLocalOciStorePath returns the path to the local OCI store, depending on
// the user running ig:
//
//   - When ig does not run as root, the per-user store ($HOME/.ig/oci-store) is
//     used, as /var/lib/ig is usually not writable by regular users.
//   - When ig runs as root (the default), the system-wide store
//     (/var/lib/ig/oci-store) is used, preserving backward compatibility.
//   - When ig runs as root and SetUseUserOciStore(true) was called (e.g. via
//     "sudo ig run --oci-store-user"), the store of the user behind sudo is
//     used instead.
func getLocalOciStorePath() string {
	// Not running as root: always use the current user's store.
	// os.Geteuid() returns -1 on platforms that do not support it (e.g.
	// Windows), which also falls into this branch.
	if os.Geteuid() != 0 {
		if p := userOciStorePath(""); p != "" {
			return p
		}
		return rootOciStore
	}

	// Running as root: optionally use the store of the user behind sudo.
	if useUserOciStore {
		// SUDO_USER is set when ig is run through sudo. Fall back to the
		// current user (root) when it is not set.
		if p := userOciStorePath(os.Getenv("SUDO_USER")); p != "" {
			return p
		}
	}

	return rootOciStore
}

// userOciStorePath returns the OCI store path inside the home directory of the
// given user. When username is empty, the home directory of the current user is
// used. It returns an empty string when the home directory cannot be resolved.
func userOciStorePath(username string) string {
	var home string
	if username == "" {
		home, _ = os.UserHomeDir()
	} else if u, err := user.Lookup(username); err == nil {
		home = u.HomeDir
	}

	if home == "" {
		return ""
	}

	return filepath.Join(home, userOciStoreSubDir)
}

// newLocalOciStore returns a localOciStore that is safe when executed
// concurrently, even from different processes.
func newLocalOciStore() (*localOciStore, error) {
	ociStorePath := getLocalOciStorePath()
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
