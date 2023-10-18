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
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/distribution/reference"
	"github.com/docker/cli/cli/config"
	"github.com/docker/cli/cli/config/configfile"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	log "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"
)

type AuthOptions struct {
	AuthFile string
	Insecure bool
}

var (
	defaultOciStore = "/var/lib/ig/oci-store"
	DefaultAuthFile = "/var/lib/ig/config.json"
)

// GadgetImage is the representation of a gadget packaged in an OCI image.
type GadgetImage struct {
	EbpfObject []byte
	Metadata   []byte
}

// GadgetImageDesc is the description of a gadget image.
type GadgetImageDesc struct {
	Repository string `column:"repository"`
	Tag        string `column:"tag"`
	Digest     string `column:"digest,width:12,fixed"`
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

// GetGadgetImage pulls the gadget image and returns the a structure representing it.
func GetGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImage, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}

	if err := pullIfNotExist(ctx, imageStore, authOpts, image); err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", image, err)
	}

	manifest, err := getImageManifestForArch(ctx, imageStore, image, authOpts)
	if err != nil {
		return nil, fmt.Errorf("getting arch manifest: %w", err)
	}

	prog, err := getEbpfProgramFromManifest(ctx, imageStore, manifest)
	if err != nil {
		return nil, fmt.Errorf("getting ebpf program: %w", err)
	}

	metadata, err := getMetadataFromManifest(ctx, imageStore, manifest)
	if err != nil {
		return nil, fmt.Errorf("getting metadata: %w", err)
	}

	return &GadgetImage{
		EbpfObject: prog,
		Metadata:   metadata,
	}, nil
}

// GetEbpfObject pulls the gadget image and returns its eBPF object for the current architecture.
func GetEbpfObject(ctx context.Context, image string, authOpts *AuthOptions) ([]byte, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}

	if err := pullIfNotExist(ctx, imageStore, authOpts, image); err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", image, err)
	}

	manifest, err := getImageManifestForArch(ctx, imageStore, image, authOpts)
	if err != nil {
		return nil, fmt.Errorf("getting arch manifest: %w", err)
	}

	return getEbpfProgramFromManifest(ctx, imageStore, manifest)
}

// GetMetadata pulls the gadget image and returns its metadata file.
func GetMetadata(ctx context.Context, image string, authOpts *AuthOptions) ([]byte, error) {
	imageStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting local oci store: %w", err)
	}

	if err := pullIfNotExist(ctx, imageStore, authOpts, image); err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", image, err)
	}

	manifest, err := getImageManifestForArch(ctx, imageStore, image, authOpts)
	if err != nil {
		return nil, fmt.Errorf("getting arch manifest: %w", err)
	}

	return getMetadataFromManifest(ctx, imageStore, manifest)
}

// PullGadgetImage pulls the gadget image and returns its descriptor.
func PullGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	repo, err := NewRepository(image, authOpts)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}
	desc, err := oras.Copy(ctx, repo, targetImage.String(), ociStore,
		targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("copying to remote repository: %w", err)
	}

	imageDesc := &GadgetImageDesc{
		Repository: targetImage.Name(),
		Digest:     desc.Digest.String(),
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

	repo, err := NewRepository(image, authOpts)
	if err != nil {
		return fmt.Errorf("creating remote repository: %w", err)
	}
	_, err = oras.Copy(ctx, repo, image, imageStore, image, oras.DefaultCopyOptions)
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

	repo, err := NewRepository(image, authOpts)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}
	desc, err := oras.Copy(context.TODO(), ociStore, targetImage.String(), repo,
		targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("copying to remote repository: %w", err)
	}

	imageDesc := &GadgetImageDesc{
		Repository: targetImage.Name(),
		Digest:     desc.Digest.String(),
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
	}
	if ref, ok := dst.(reference.Tagged); ok {
		imageDesc.Tag = ref.Tag()
	}
	return imageDesc, nil
}

// ListGadgetImages lists all the gadget images.
func ListGadgetImages(ctx context.Context) ([]*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	imageColumns := []*GadgetImageDesc{}
	err = ociStore.Tags(ctx, "", func(tags []string) error {
		for _, fullTag := range tags {
			repository, err := getRepositoryFromImage(fullTag)
			if err != nil {
				log.Debugf("getting repository from image %q: %s", fullTag, err)
				continue
			}
			tag, err := getTagFromImage(fullTag)
			if err != nil {
				log.Debugf("getting tag from image %q: %s", fullTag, err)
				continue
			}
			imageColumn := &GadgetImageDesc{
				Repository: repository,
				Tag:        tag,
			}

			desc, err := ociStore.Resolve(ctx, fullTag)
			if err != nil {
				log.Debugf("Found tag %q but couldn't get a descriptor for it: %v", fullTag, err)
				continue
			}
			imageColumn.Digest = desc.Digest.String()
			imageColumns = append(imageColumns, imageColumn)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("listing all tags: %w", err)
	}

	return imageColumns, nil
}

func getTagFromImage(image string) (string, error) {
	repo, err := reference.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parsing image %q: %w", image, err)
	}
	tagged, ok := repo.(reference.Tagged)
	if !ok {
		return "latest", nil
	}
	return tagged.Tag(), nil
}

func getRepositoryFromImage(image string) (string, error) {
	repo, err := reference.Parse(image)
	if err != nil {
		return "", fmt.Errorf("parsing image %q: %w", image, err)
	}
	if named, ok := repo.(reference.Named); ok {
		return named.Name(), nil
	}
	return "", fmt.Errorf("image has to be a named reference")
}

func normalizeImageName(image string) (reference.Named, error) {
	name, err := reference.ParseNormalizedNamed(image)
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

	authFileReader, err := os.Open(authOptions.AuthFile)
	if err != nil {
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
			Username:    authConfig.Username,
			Password:    authConfig.Password,
			AccessToken: authConfig.Auth,
		}),
	}, nil
}

// NewRepository creates a client to the remote repository identified by
// image using the given auth options.
func NewRepository(image string, authOpts *AuthOptions) (*remote.Repository, error) {
	repository, err := getRepositoryFromImage(image)
	if err != nil {
		return nil, fmt.Errorf("getting repository from image %q: %w", image, err)
	}
	repo, err := remote.NewRepository(repository)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}
	repo.PlainHTTP = authOpts.Insecure
	if !authOpts.Insecure {
		client, err := newAuthClient(repository, authOpts)
		if err != nil {
			return nil, fmt.Errorf("creating auth client: %w", err)
		}
		repo.Client = client
	}

	return repo, nil
}

func getImageListDescriptor(ctx context.Context, imageStore oras.ReadOnlyTarget, reference string) (ocispec.Index, error) {
	imageListDescriptor, err := imageStore.Resolve(ctx, reference)
	if err != nil {
		return ocispec.Index{}, fmt.Errorf("resolving image %q: %w", reference, err)
	}
	if imageListDescriptor.MediaType != ocispec.MediaTypeImageIndex {
		return ocispec.Index{}, fmt.Errorf("image %q is not an image index", reference)
	}

	reader, err := imageStore.Fetch(ctx, imageListDescriptor)
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

func getHostArchManifest(imageStore oras.ReadOnlyTarget, index ocispec.Index) (*ocispec.Manifest, error) {
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

func getMetadataFromManifest(ctx context.Context, target oras.Target, manifest *ocispec.Manifest) ([]byte, error) {
	// metadata is optional
	if manifest.Config.Size == 0 {
		return nil, nil
	}

	metadata, err := getContentFromDescriptor(ctx, target, manifest.Config)
	if err != nil {
		return nil, fmt.Errorf("getting metadata from descriptor: %w", err)
	}

	return metadata, nil
}

func getEbpfProgramFromManifest(ctx context.Context, target oras.Target, manifest *ocispec.Manifest) ([]byte, error) {
	if len(manifest.Layers) != 1 {
		return nil, fmt.Errorf("expected exactly one layer, got %d", len(manifest.Layers))
	}
	prog, err := getContentFromDescriptor(ctx, target, manifest.Layers[0])
	if err != nil {
		return nil, fmt.Errorf("getting ebpf program from descriptor: %w", err)
	}
	if len(prog) == 0 {
		return nil, errors.New("program is empty")
	}
	return prog, nil
}

func getContentFromDescriptor(ctx context.Context, imageStore oras.ReadOnlyTarget, desc ocispec.Descriptor) ([]byte, error) {
	reader, err := imageStore.Fetch(ctx, desc)
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

func getImageManifestForArch(ctx context.Context, target oras.Target, image string, authOpts *AuthOptions) (*ocispec.Manifest, error) {
	imageRef, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}

	index, err := getImageListDescriptor(ctx, target, imageRef.String())
	if err != nil {
		return nil, fmt.Errorf("getting image list descriptor: %w", err)
	}

	manifest, err := getHostArchManifest(target, index)
	if err != nil {
		return nil, fmt.Errorf("getting arch manifest: %w", err)
	}
	return manifest, nil
}
