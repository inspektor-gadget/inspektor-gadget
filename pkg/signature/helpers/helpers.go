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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"unsafe"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
)

func GetImageDigest(ctx context.Context, store oras.Target, imageRef string) (string, error) {
	desc, err := store.Resolve(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	return desc.Digest.String(), nil
}

func CraftSignatureIndexTag(digest string) (string, error) {
	// When signature are used as reference artifacts, we can find them by using
	// this tag:
	// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#referrers-tag-schema
	// This is used by default for Notation:
	// https://github.com/notaryproject/notation/commit/0f556be80571
	// And only when using specific flag and options for Cosign:
	// https://www.chainguard.dev/unchained/building-towards-oci-v1-1-support-in-cosign
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong digest, expected two parts, got %d", len(parts))
	}

	return fmt.Sprintf("%s-%s", parts[0], parts[1]), nil
}

func CraftCosignSignatureTag(digest string) (string, error) {
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong digest, expected two parts, got %d", len(parts))
	}

	return fmt.Sprintf("%s-%s.sig", parts[0], parts[1]), nil
}

// Taken from:
// https://github.com/sigstore/cosign/blob/ee3d9fe1c55e/pkg/cosign/bundle/protobundle.go#L36
const bundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

func FindBundleTag(imageStore oras.ReadOnlyTarget, imageDigest string) (string, error) {
	reflectedStore := reflect.ValueOf(imageStore).Elem()
	rootField := reflectedStore.FieldByName("root")
	imageStoreRootPath := *(*string)(unsafe.Pointer(rootField.UnsafeAddr()))
	if imageStoreRootPath == "" {
		return "", errors.New("local image store path cannot be empty")
	}

	blobsPath := filepath.Join(imageStoreRootPath, "blobs", "sha256")
	bundleTag := ""
	err := fs.WalkDir(os.DirFS(blobsPath), ".", func (path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		manifestBytes, err := os.ReadFile(filepath.Join(blobsPath, path))
		if err != nil {
			return fmt.Errorf("reading %q: %w", path, err)
		}

		manifest := &ocispec.Manifest{}
		err = json.Unmarshal(manifestBytes, manifest)
		if err != nil {
			return fmt.Errorf("decoding manifest: %w", err)
		}

		if manifest.Subject == nil {
			return nil
		}

		if manifest.Subject.Digest.String() != imageDigest {
			return nil
		}

		for _, layer := range manifest.Layers {
			if layer.MediaType == bundleV03MediaType {
				bundleTag = "sha256:" + entry.Name()

				return fs.SkipAll
			}
		}

		return filepath.SkipAll
	})
	if err != nil {
		return "", fmt.Errorf("walking %q: %w", blobsPath, err)
	}

	return bundleTag, nil
}

func CopySigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, digest string, craftSigningInfoTag func(digest string) (string, error)) error {
	signingInfoTag, err := craftSigningInfoTag(digest)
	if err != nil {
		return fmt.Errorf("crafting signing information tag: %w", err)
	}

	_, err = oras.Copy(ctx, src, signingInfoTag, dst, signingInfoTag, oras.DefaultCopyOptions)
	return err
}
