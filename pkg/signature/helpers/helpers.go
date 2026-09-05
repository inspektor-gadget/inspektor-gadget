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
	"strings"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry"
)

func GetImageDigest(ctx context.Context, store oras.ReadOnlyGraphTarget, imageRef string) (string, error) {
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

const (
	BundleV03MediaType = "application/vnd.dev.sigstore.bundle.v0.3+json" // https://github.com/sigstore/cosign/blob/ee3d9fe1c55e/pkg/cosign/bundle/protobundle.go#L36

	CosignSignatureMediaType = "application/vnd.dev.cosign.artifact.sig.v1+json" // https://github.com/sigstore/cosign/blob/45bda40b8ef4/internal/pkg/oci/remote/remote.go#L24

	NotationSignatureMediatype = "application/vnd.cncf.notary.signature" // https://github.com/notaryproject/notation-go/blob/a48f22835cb5/registry/mediatype.go#L18

	// maxReferrersToInspect bounds unfiltered scans so signature discovery does
	// not inspect an unbounded number of unrelated referrers.
	maxReferrersToInspect = 42
)

func FindBundleTag(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string) (string, error) {
	return findReferrerTag(ctx, imageStore, imageDigest, BundleV03MediaType)
}

func FindOCI11SignatureTag(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string) (string, error) {
	// OCI 1.1 can be used with both notation and cosign, in these two cases this
	// will store different kind of signature (one for notation and one for
	// cosign).
	// Let's first try to find the signature tag using the referrers API for both
	// type and default to crafting it.
	// This can occur if the registry does not support the referrers API:
	// https://github.com/opencontainers/distribution-spec/blob/v1.1.1/spec.md#referrers-tag-schema
	signingInfoTag, err := FindCosignSignatureTag(ctx, imageStore, imageDigest)
	if err == nil {
		return signingInfoTag, nil
	}

	signingInfoTag, err = FindNotationSignatureTag(ctx, imageStore, imageDigest)
	if err == nil {
		return signingInfoTag, nil
	}

	return CraftSignatureIndexTag(imageDigest)
}

func FindNotationSignatureTag(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string) (string, error) {
	return findReferrerTag(ctx, imageStore, imageDigest, NotationSignatureMediatype)
}

func FindCosignSignatureTag(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string) (string, error) {
	return findReferrerTag(ctx, imageStore, imageDigest, CosignSignatureMediaType)
}

func findReferrerTag(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string, artifactType string) (string, error) {
	descriptors, err := findReferrerTags(ctx, imageStore, imageDigest, artifactType)
	if err != nil {
		return "", err
	}

	if len(descriptors) > 1 {
		return "", multipleReferrersError(artifactType)
	}

	return descriptors[0], nil
}

func findReferrerTags(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, imageDigest string, artifactType string) ([]string, error) {
	desc, err := imageStore.Resolve(ctx, imageDigest)
	if err != nil {
		return nil, fmt.Errorf("resolving %s: %w", imageDigest, err)
	}

	descriptors, err := findReferrersByManifestInspection(ctx, imageStore, desc, artifactType)
	if err != nil {
		return nil, fmt.Errorf("searching for %q referring %q: %w", artifactType, imageDigest, err)
	}

	if len(descriptors) == 0 {
		return nil, errors.New("no referrers found")
	}

	tags := make([]string, 0, len(descriptors))
	for _, descriptor := range descriptors {
		tags = append(tags, descriptor.Digest.String())
	}

	return tags, nil
}

func findReferrersByManifestInspection(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, desc ocispec.Descriptor, artifactType string) ([]ocispec.Descriptor, error) {
	matches := []ocispec.Descriptor{}
	referrersInspected := 0

	// artifactType filtering is optional for registries, so inspect unfiltered
	// referrers. Use pagination when available to avoid accumulating pages.
	if referrerLister, ok := imageStore.(registry.ReferrerLister); ok {
		err := referrerLister.Referrers(ctx, desc, "", func(referrers []ocispec.Descriptor) error {
			return processReferrers(ctx, imageStore, referrers, artifactType, &matches, &referrersInspected)
		})
		if err != nil {
			return nil, fmt.Errorf("listing referrers without artifact type filter: %w", err)
		}

		return matches, nil
	}

	referrers, err := registry.Referrers(ctx, imageStore, desc, "")
	if err != nil {
		return nil, fmt.Errorf("listing referrers without artifact type filter: %w", err)
	}

	if err := processReferrers(ctx, imageStore, referrers, artifactType, &matches, &referrersInspected); err != nil {
		return nil, err
	}

	return matches, nil
}

func processReferrers(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, referrers []ocispec.Descriptor, artifactType string, matches *[]ocispec.Descriptor, referrersInspected *int) error {
	if *referrersInspected+len(referrers) > maxReferrersToInspect {
		return fmt.Errorf("inspecting more than %d referrers is not supported", maxReferrersToInspect)
	}
	*referrersInspected += len(referrers)

	for _, descriptor := range referrers {
		match, descriptor, err := referrerMatchesArtifactType(ctx, imageStore, descriptor, artifactType)
		if err != nil {
			return err
		}
		if match {
			*matches = append(*matches, descriptor)
			if len(*matches) > 1 {
				return multipleReferrersError(artifactType)
			}
		}
	}

	return nil
}

func referrerMatchesArtifactType(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, descriptor ocispec.Descriptor, artifactType string) (bool, ocispec.Descriptor, error) {
	if descriptor.ArtifactType == artifactType {
		return true, descriptor, nil
	}

	referrerArtifactType, err := getManifestArtifactType(ctx, imageStore, descriptor.Digest.String())
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return false, descriptor, nil
		}

		return false, descriptor, fmt.Errorf("getting manifest artifact type for %q: %w", descriptor.Digest, err)
	}

	if referrerArtifactType != artifactType {
		return false, descriptor, nil
	}

	descriptor.ArtifactType = referrerArtifactType
	return true, descriptor, nil
}

func multipleReferrersError(artifactType string) error {
	return fmt.Errorf("images with several %q referrers are not supported", artifactType)
}

func getManifestArtifactType(ctx context.Context, imageStore oras.ReadOnlyGraphTarget, reference string) (string, error) {
	_, manifestBytes, err := oras.FetchBytes(ctx, imageStore, reference, oras.DefaultFetchBytesOptions)
	if err != nil {
		return "", fmt.Errorf("fetching manifest: %w", err)
	}

	manifest := &ocispec.Manifest{}
	if err := json.Unmarshal(manifestBytes, manifest); err != nil {
		return "", fmt.Errorf("decoding manifest: %w", err)
	}

	return manifest.ArtifactType, nil
}

func CopySigningInformation(ctx context.Context, src oras.ReadOnlyGraphTarget, dst oras.Target, digest string, craftSigningInfoTag func(digest string) (string, error)) error {
	signingInfoTag, err := craftSigningInfoTag(digest)
	if err != nil {
		return fmt.Errorf("crafting signing information tag: %w", err)
	}

	_, err = oras.Copy(ctx, src, signingInfoTag, dst, signingInfoTag, oras.DefaultCopyOptions)
	return err
}
