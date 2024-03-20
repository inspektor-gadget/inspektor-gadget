// Copyright 2023-2024 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

type AuthOptions struct {
	AuthFile    string
	SecretBytes []byte
	Insecure    bool
}

const (
	defaultOciStore = "/var/lib/ig/oci-store"
	DefaultAuthFile = "/var/lib/ig/config.json"

	PullImageAlways  = "always"
	PullImageMissing = "missing"
	PullImageNever   = "never"
)

const (
	defaultDomain      = "ghcr.io"
	officialRepoPrefix = "inspektor-gadget/gadget/"
	// localhost is treated as a special value for domain-name. Any other
	// domain-name without a "." or a ":port" are considered a path component.
	localhost = "localhost"
)

// GadgetImage is the representation of a gadget packaged in an OCI image.
type GadgetImage struct {
	EbpfObject []byte
	WasmObject []byte
	Metadata   []byte
}

// GadgetImageDesc is the description of a gadget image.
type GadgetImageDesc struct {
	Repository string `column:"repository"`
	Tag        string `column:"tag"`
	Digest     string `column:"digest,width:12,fixed"`
	Created    string `column:"created"`
}

func (d *GadgetImageDesc) String() string {
	if d.Tag == "" && d.Repository == "" {
		return fmt.Sprintf("@%s", d.Digest)
	}
	return fmt.Sprintf("%s:%s@%s", d.Repository, d.Tag, d.Digest)
}

func getLocalOciStore() (*oci.Store, error) {
	if err := os.MkdirAll(filepath.Dir(defaultOciStore), 0o700); err != nil {
		return nil, err
	}
	return oci.New(defaultOciStore)
}

func getTimeFromAnnotations(annotations map[string]string) string {
	created, _ := annotations[ocispec.AnnotationCreated]
	return created
}

// GetGadgetImage pulls the gadget image according to the pull policy and returns
// a GadgetImage structure representing it.
func GetGadgetImage(ctx context.Context, image string, authOpts *AuthOptions, pullPolicy string) (*GadgetImage, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}

	err = ensureImage(ctx, imageStore, image, authOpts, pullPolicy)
	if err != nil {
		return nil, fmt.Errorf("ensuring image presence: %w", err)
	}

	manifest, err := getManifestForHost(ctx, imageStore, image)
	if err != nil {
		return nil, fmt.Errorf("getting arch manifest: %w", err)
	}

	prog, err := getLayerFromManifest(ctx, imageStore, manifest, eBPFObjectMediaType)
	if err != nil {
		return nil, fmt.Errorf("getting ebpf program: %w", err)
	}
	if prog == nil {
		return nil, fmt.Errorf("no ebpf program found")
	}

	wasm, err := getLayerFromManifest(ctx, imageStore, manifest, wasmObjectMediaType)
	if err != nil {
		return nil, fmt.Errorf("getting wasm program: %w", err)
	}

	metadata, err := getMetadataFromManifest(ctx, imageStore, manifest)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}

	return &GadgetImage{
		EbpfObject: prog,
		WasmObject: wasm,
		Metadata:   metadata,
	}, nil
}

// PullGadgetImage pulls the gadget image into the local oci store and returns its descriptor.
func PullGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	return pullGadgetImageToStore(ctx, ociStore, image, authOpts)
}

// pullGadgetImageToStore pulls the gadget image into the given store and returns its descriptor.
func pullGadgetImageToStore(ctx context.Context, imageStore oras.Target, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}
	repo, err := newRepository(targetImage, authOpts)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	desc, err := oras.Copy(ctx, repo, targetImage.String(), imageStore,
		targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("copying to remote repository: %w", err)
	}

	imageDesc := &GadgetImageDesc{
		Repository: targetImage.Name(),
		Digest:     desc.Digest.String(),
		Created:    "", // Unfortunately, oras.Copy does not return annotations
	}

	if ref, ok := targetImage.(reference.Tagged); ok {
		imageDesc.Tag = ref.Tag()
	}
	return imageDesc, nil
}

func pullIfNotExist(ctx context.Context, imageStore oras.Target, authOpts *AuthOptions, image string) error {
	targetImage, err := normalizeImageName(image)
	if err != nil {
		return fmt.Errorf("normalizing image: %w", err)
	}

	_, err = imageStore.Resolve(ctx, targetImage.String())
	if err == nil {
		return nil
	}
	if !errors.Is(err, errdef.ErrNotFound) {
		return fmt.Errorf("resolving image %q: %w", image, err)
	}

	repo, err := newRepository(targetImage, authOpts)
	if err != nil {
		return fmt.Errorf("creating remote repository: %w", err)
	}
	_, err = oras.Copy(ctx, repo, targetImage.String(), imageStore, targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return fmt.Errorf("downloading to local repository: %w", err)
	}
	return nil
}

// PushGadgetImage pushes the gadget image and returns its descriptor.
func PushGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}
	repo, err := newRepository(targetImage, authOpts)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	desc, err := oras.Copy(context.TODO(), ociStore, targetImage.String(), repo,
		targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("copying to remote repository: %w", err)
	}

	imageDesc := &GadgetImageDesc{
		Repository: targetImage.Name(),
		Digest:     desc.Digest.String(),
		Created:    "", // Unfortunately, oras.Copy does not return annotations
	}
	if ref, ok := targetImage.(reference.Tagged); ok {
		imageDesc.Tag = ref.Tag()
	}
	return imageDesc, nil
}

// TagGadgetImage tags the src image with the dst image.
func TagGadgetImage(ctx context.Context, srcImage, dstImage string) (*GadgetImageDesc, error) {
	src, err := normalizeImageName(srcImage)
	if err != nil {
		return nil, fmt.Errorf("normalizing src image: %w", err)
	}
	dst, err := normalizeImageName(dstImage)
	if err != nil {
		return nil, fmt.Errorf("normalizing dst image: %w", err)
	}

	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	targetDescriptor, err := ociStore.Resolve(context.TODO(), src.String())
	if err != nil {
		// Error message not that helpful
		return nil, fmt.Errorf("resolving src: %w", err)
	}
	ociStore.Tag(context.TODO(), targetDescriptor, dst.String())

	imageDesc := &GadgetImageDesc{
		Repository: dst.Name(),
		Digest:     targetDescriptor.Digest.String(),
		Created:    getTimeFromAnnotations(targetDescriptor.Annotations),
	}
	if ref, ok := dst.(reference.Tagged); ok {
		imageDesc.Tag = ref.Tag()
	}
	return imageDesc, nil
}

func listGadgetImages(ctx context.Context, store *oci.Store) ([]*GadgetImageDesc, error) {
	images := []*GadgetImageDesc{}
	err := store.Tags(ctx, "", func(tags []string) error {
		for _, fullTag := range tags {
			parsed, err := reference.Parse(fullTag)
			if err != nil {
				log.Debugf("parsing image %q: %s", fullTag, err)
				continue
			}

			var repository string
			if named, ok := parsed.(reference.Named); ok {
				repository = named.Name()
			}

			tag := "latest"
			if tagged, ok := parsed.(reference.Tagged); ok {
				tag = tagged.Tag()
			}

			image := &GadgetImageDesc{
				Repository: repository,
				Tag:        tag,
			}

			desc, err := store.Resolve(ctx, fullTag)
			if err != nil {
				log.Debugf("Found tag %q but couldn't get a descriptor for it: %v", fullTag, err)
				continue
			}
			image.Digest = desc.Digest.String()

			manifest, err := getManifestForHost(ctx, store, fullTag)
			if err != nil {
				log.Debugf("Getting manifest for %q: %v", fullTag, err)
				continue
			}

			image.Created = getTimeFromAnnotations(manifest.Annotations)

			images = append(images, image)
		}
		return nil
	})

	return images, err
}

// ListGadgetImages lists all the gadget images.
func ListGadgetImages(ctx context.Context) ([]*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	images, err := listGadgetImages(ctx, ociStore)
	if err != nil {
		return nil, fmt.Errorf("listing all tags: %w", err)
	}

	for _, image := range images {
		image.Repository = strings.TrimPrefix(image.Repository, defaultDomain+"/"+officialRepoPrefix)
	}

	return images, nil
}

// DeleteGadgetImage removes the given image.
func DeleteGadgetImage(ctx context.Context, image string) error {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return fmt.Errorf("getting oci store: %w", err)
	}

	targetImage, err := normalizeImageName(image)
	if err != nil {
		return fmt.Errorf("normalizing image: %w", err)
	}

	fullName := targetImage.String()
	descriptor, err := ociStore.Resolve(ctx, fullName)
	if err != nil {
		return fmt.Errorf("resolving image: %w", err)
	}

	images, err := listGadgetImages(ctx, ociStore)
	if err != nil {
		return fmt.Errorf("listing images: %w", err)
	}

	digest := descriptor.Digest.String()
	for _, img := range images {
		imgFullName := fmt.Sprintf("%s:%s", img.Repository, img.Tag)
		if img.Digest == digest && imgFullName != fullName {
			// We cannot blindly delete a whole image tree.
			// Indeed, it is possible for several image names to point to the same
			// underlying image, like:
			// REPOSITORY            TAG    DIGEST
			// docker.io/library/bar latest f959f580ba01
			// docker.io/library/foo latest f959f580ba01
			// Where foo and bar are different names referencing the same image, as
			// the digest shows.
			// In this case, we just untag the image name given by the user.
			return ociStore.Untag(ctx, fullName)
		}
	}

	err = ociStore.Delete(ctx, descriptor)
	if err != nil {
		return err
	}

	return ociStore.GC(ctx)
}

// splitIGDomain splits a repository name to domain and remote-name.
// If no valid domain is found, the default domain is used. Repository name
// needs to be already validated before.
// Inspired on https://github.com/distribution/reference/blob/v0.5.0/normalize.go#L126
// TODO: Ideally we should use the upstream function but docker.io is harcoded there
// https://github.com/distribution/reference/blob/v0.5.0/normalize.go#L31
func splitIGDomain(name string) (domain, remainder string) {
	i := strings.IndexRune(name, '/')
	if i == -1 || (!strings.ContainsAny(name[:i], ".:") && name[:i] != localhost && strings.ToLower(name[:i]) == name[:i]) {
		domain, remainder = defaultDomain, name
	} else {
		domain, remainder = name[:i], name[i+1:]
	}
	if domain == defaultDomain && !strings.ContainsRune(remainder, '/') {
		remainder = officialRepoPrefix + remainder
	}
	return
}

func normalizeImageName(image string) (reference.Named, error) {
	// Use the default gadget's registry if no domain is specified.
	domain, remainer := splitIGDomain(image)

	name, err := reference.ParseNormalizedNamed(domain + "/" + remainer)
	if err != nil {
		return nil, fmt.Errorf("parsing normalized image %q: %w", image, err)
	}
	return reference.TagNameOnly(name), nil
}

func getHostString(repository string) (string, error) {
	repo, err := reference.Parse(repository)
	if err != nil {
		return "", fmt.Errorf("parsing repository %q: %w", repository, err)
	}
	if named, ok := repo.(reference.Named); ok {
		return reference.Domain(named), nil
	}
	return "", fmt.Errorf("image has to be a named reference")
}

func newAuthClient(repository string, authOptions *AuthOptions) (*oras_auth.Client, error) {
	log.Debugf("Using auth file %q", authOptions.AuthFile)

	var cfg *configfile.ConfigFile
	var err error

	if authOptions.SecretBytes != nil && len(authOptions.SecretBytes) != 0 {
		cfg, err = config.LoadFromReader(bytes.NewReader(authOptions.SecretBytes))
		if err != nil {
			return nil, fmt.Errorf("loading auth config: %w", err)
		}
	} else if authFileReader, err := os.Open(authOptions.AuthFile); err != nil {
		// If the AuthFile was not set explicitly, we allow to fall back to the docker auth,
		// otherwise we fail to avoid masking an error from the user
		if !errors.Is(err, os.ErrNotExist) || authOptions.AuthFile != DefaultAuthFile {
			return nil, fmt.Errorf("opening auth file %q: %w", authOptions.AuthFile, err)
		}

		log.Debugf("Couldn't find default auth file %q...", authOptions.AuthFile)
		log.Debugf("Using default docker auth file instead")
		log.Debugf("$HOME: %q", os.Getenv("HOME"))

		cfg, err = config.Load("")
		if err != nil {
			return nil, fmt.Errorf("loading auth config: %w", err)
		}

	} else {
		defer authFileReader.Close()
		cfg, err = config.LoadFromReader(authFileReader)
		if err != nil {
			return nil, fmt.Errorf("loading auth config: %w", err)
		}
	}

	hostString, err := getHostString(repository)
	if err != nil {
		return nil, fmt.Errorf("getting host string: %w", err)
	}
	authConfig, err := cfg.GetAuthConfig(hostString)
	if err != nil {
		return nil, fmt.Errorf("getting auth config: %w", err)
	}

	return &oras_auth.Client{
		Credential: oras_auth.StaticCredential(hostString, oras_auth.Credential{
			Username:     authConfig.Username,
			Password:     authConfig.Password,
			AccessToken:  authConfig.Auth,
			RefreshToken: authConfig.IdentityToken,
		}),
	}, nil
}

// newRepository creates a client to the remote repository identified by
// image using the given auth options.
func newRepository(image reference.Named, authOpts *AuthOptions) (*remote.Repository, error) {
	repo, err := remote.NewRepository(image.Name())
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	repo.PlainHTTP = authOpts.Insecure
	if !authOpts.Insecure {
		client, err := newAuthClient(image.Name(), authOpts)
		if err != nil {
			return nil, fmt.Errorf("creating auth client: %w", err)
		}
		repo.Client = client
	}

	return repo, nil
}

func getImageListDescriptor(ctx context.Context, target oras.ReadOnlyTarget, reference string) (ocispec.Index, error) {
	imageListDescriptor, err := target.Resolve(ctx, reference)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("resolving image %q: %w", reference, err)
	}
	if imageListDescriptor.MediaType != ocispec.MediaTypeImageIndex {
		return ocispec.Index{}, fmt.Errorf("image %q is not an image index", reference)
	}

	reader, err := target.Fetch(ctx, imageListDescriptor)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("fetching image index: %w", err)
	}
	defer reader.Close()

	var index ocispec.Index
	if err = json.NewDecoder(reader).Decode(&index); err != nil {
		return ocispec.Index{}, fmt.Errorf("unmarshalling image index: %w", err)
	}
	return index, nil
}

func getArchManifest(imageStore oras.ReadOnlyTarget, index ocispec.Index) (*ocispec.Manifest, error) {
	var manifestDesc ocispec.Descriptor
	for _, indexManifest := range index.Manifests {
		// TODO: Check docker code
		if indexManifest.Platform.Architecture == runtime.GOARCH {
			manifestDesc = indexManifest
			break
		}
	}
	if manifestDesc.Digest == "" {
		return nil, fmt.Errorf("no manifest found for architecture %q", runtime.GOARCH)
	}

	reader, err := imageStore.Fetch(context.TODO(), manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("fetching manifest: %w", err)
	}
	defer reader.Close()

	var manifest ocispec.Manifest
	if err = json.NewDecoder(reader).Decode(&manifest); err != nil {
		return nil, fmt.Errorf("unmarshalling manifest: %w", err)
	}
	return &manifest, nil
}

func getMetadataFromManifest(ctx context.Context, fetcher content.Fetcher, manifest *ocispec.Manifest) ([]byte, error) {
	metadataBytes, err := getContentBytesFromDescriptor(ctx, fetcher, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("getting metadata from descriptor: %w", err)
	}

	return metadataBytes, nil
}

func getLayerFromManifest(ctx context.Context, fetcher content.Fetcher, manifest *ocispec.Manifest, mediaType string) ([]byte, error) {
	var layer ocispec.Descriptor
	layerCount := 0
	for _, l := range manifest.Layers {
		if l.MediaType == mediaType {
			layer = l
			layerCount++
		}
	}
	if layerCount == 0 {
		return nil, nil
	}
	if layerCount != 1 {
		return nil, fmt.Errorf("expected exactly one layer with media type %q, got %d", mediaType, layerCount)
	}
	layerBytes, err := getContentBytesFromDescriptor(ctx, fetcher, layer)
	if err != nil {
		return nil, fmt.Errorf("getting layer %q from descriptor: %w", mediaType, err)
	}
	if len(layerBytes) == 0 {
		return nil, errors.New("layer is empty")
	}
	return layerBytes, nil
}

func getContentBytesFromDescriptor(ctx context.Context, fetcher content.Fetcher, desc ocispec.Descriptor) ([]byte, error) {
	reader, err := fetcher.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching descriptor: %w", err)
	}
	defer reader.Close()
	bytes, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("reading descriptor: %w", err)
	}
	return bytes, nil
}

func ensureImage(ctx context.Context, imageStore oras.Target, image string, authOpts *AuthOptions, pullPolicy string) error {
	switch pullPolicy {
	case PullImageAlways:
		_, err := pullGadgetImageToStore(ctx, imageStore, image, authOpts)
		if err != nil {
			return fmt.Errorf("pulling image (always) %q: %w", image, err)
		}
	case PullImageMissing:
		if err := pullIfNotExist(ctx, imageStore, authOpts, image); err != nil {
			return fmt.Errorf("pulling image (if missing) %q: %w", image, err)
		}
	case PullImageNever:
		// Just check if the image exists to report a better error message
		targetImage, err := normalizeImageName(image)
		if err != nil {
			return fmt.Errorf("normalizing image: %w", err)
		}
		if _, err := imageStore.Resolve(ctx, targetImage.String()); err != nil {
			return fmt.Errorf("resolving image %q on local registry: %w", targetImage.String(), err)
		}
	}
	return nil
}

// EnsureImage ensures the image is present in the local store
func EnsureImage(ctx context.Context, image string, authOpts *AuthOptions, pullPolicy string) error {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return fmt.Errorf("getting local oci store: %w", err)
	}

	return ensureImage(ctx, imageStore, image, authOpts, pullPolicy)
}

func getManifestForHost(ctx context.Context, target oras.ReadOnlyTarget, image string) (*ocispec.Manifest, error) {
	index, err := getIndex(ctx, target, image)
	if err != nil {
		return nil, fmt.Errorf("getting index: %w", err)
	}

	var manifestDesc *ocispec.Descriptor
	for _, indexManifest := range index.Manifests {
		// TODO: Check docker code
		if indexManifest.Platform.Architecture == runtime.GOARCH {
			manifestDesc = &indexManifest
			break
		}
	}
	if manifestDesc == nil {
		return nil, fmt.Errorf("no manifest found for architecture %q", runtime.GOARCH)
	}

	manifestBytes, err := getContentBytesFromDescriptor(ctx, target, *manifestDesc)
	if err != nil {
		return nil, fmt.Errorf("getting content from descriptor: %w", err)
	}

	manifest := &ocispec.Manifest{}
	err = json.Unmarshal(manifestBytes, manifest)
	if err != nil {
		return nil, fmt.Errorf("decoding manifest: %w", err)
	}
	return manifest, nil
}

func GetManifestForHost(ctx context.Context, image string) (*ocispec.Manifest, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}
	return getManifestForHost(ctx, imageStore, image)
}

// getIndex gets an index for the given image
func getIndex(ctx context.Context, target oras.ReadOnlyTarget, image string) (*ocispec.Index, error) {
	imageRef, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}

	index, err := getImageListDescriptor(ctx, target, imageRef.String())
	if err != nil {
		return nil, fmt.Errorf("getting image list descriptor: %w", err)
	}

	return &index, nil
}

func GetContentFromDescriptor(ctx context.Context, desc ocispec.Descriptor) (io.ReadCloser, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}

	reader, err := imageStore.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching descriptor: %w", err)
	}
	return reader, nil
}
