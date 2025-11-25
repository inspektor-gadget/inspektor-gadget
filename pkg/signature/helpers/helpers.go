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
	"fmt"
	"strings"

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

func CopySigningInformation(ctx context.Context, src oras.ReadOnlyTarget, dst oras.Target, digest string, craftSigningInfoTag func(digest string) (string, error)) error {
	signingInfoTag, err := craftSigningInfoTag(digest)
	if err != nil {
		return fmt.Errorf("crafting signing information tag: %w", err)
	}

	_, err = oras.Copy(ctx, src, signingInfoTag, dst, signingInfoTag, oras.DefaultCopyOptions)
	return err
}
