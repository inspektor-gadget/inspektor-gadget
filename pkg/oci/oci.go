// Copyright 2023-2025 The Inspektor Gadget authors
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
	"archive/tar"
	"bytes"
	"cmp"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

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

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	signatureverifier "github.com/inspektor-gadget/inspektor-gadget/pkg/signature-verifier"
)

type AuthOptions struct {
	AuthFile    string
	SecretBytes []byte
	// InsecureRegistries is a list of registries that should be accessed over
	// plain HTTP.
	InsecureRegistries []string
	DisallowPulling    bool
}

type AllowedGadgetsOptions struct {
	AllowedGadgets []string
}

type VerifyOptions struct {
	signatureverifier.VerifyOptions

	VerifySignature bool
}

type ImageOptions struct {
	AuthOptions
	VerifyOptions
	AllowedGadgetsOptions

	Logger logger.Logger
}

const (
	defaultOciStore = "/var/lib/ig/oci-store"
	DefaultAuthFile = "/var/lib/ig/config.json"

	PullImageAlways  = "always"
	PullImageMissing = "missing"
	PullImageNever   = "never"
)

var (
	DefaultDomain      = "ghcr.io"
	officialRepoPrefix = "inspektor-gadget/gadget/"
)

const (
	// localhost is treated as a special value for domain-name. Any other
	// domain-name without a "." or a ":port" are considered a path component.
	localhost = "localhost"
)

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

func getTimeFromAnnotations(annotations map[string]string) string {
	return annotations[ocispec.AnnotationCreated]
}

// PullGadgetImage pulls the gadget image into the local oci store and returns its descriptor.
func PullGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	var desc *GadgetImageDesc
	err := retry("PullGadgetImage", func() error {
		var err error
		desc, err = pullGadgetImage(ctx, image, authOpts)
		return err
	})

	return desc, err
}

func pullGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	ociStore, err := newLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	desc, err := pullGadgetImageToStore(ctx, ociStore.Store, image, authOpts)
	if err != nil {
		return nil, err
	}

	if err := ociStore.saveIndexWithLock(); err != nil {
		return nil, err
	}

	return desc, nil
}

// pullGadgetImageToStore pulls the gadget image into the given store and returns its descriptor.
func pullGadgetImageToStore(ctx context.Context, imageStore oras.Target, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}

	desc, err := pullImage(ctx, targetImage, imageStore, authOpts)
	if err != nil {
		return nil, fmt.Errorf("pulling image %q: %w", image, err)
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

	_, err = pullImage(ctx, targetImage, imageStore, authOpts)
	if err != nil {
		return fmt.Errorf("pulling image %q: %w", image, err)
	}

	return nil
}

func pullImage(ctx context.Context, targetImage reference.Named, imageStore oras.Target, authOpts *AuthOptions) (*ocispec.Descriptor, error) {
	if authOpts.DisallowPulling {
		return nil, errors.New("pulling is disallowed")
	}

	repo, err := newRepository(targetImage, authOpts)
	if err != nil {
		return nil, fmt.Errorf("creating remote repository: %w", err)
	}

	desc, err := oras.Copy(ctx, repo, targetImage.String(), imageStore,
		targetImage.String(), oras.DefaultCopyOptions)
	if err != nil {
		return nil, fmt.Errorf("copying to local repository: %w", err)
	}

	imageDigest := desc.Digest.String()
	if err := signatureverifier.PullSigningInformation(ctx, repo, imageStore, imageDigest); err != nil {
		log.Warnf("error pulling signature: %v", err)
		// it's not a requirement to have a signature for pulling the image
		return &desc, nil
	}

	return &desc, nil
}

// PushGadgetImage pushes the gadget image and returns its descriptor.
func PushGadgetImage(ctx context.Context, image string, authOpts *AuthOptions) (*GadgetImageDesc, error) {
	ociStore, err := newLocalOciStore()
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
	var desc *GadgetImageDesc
	err := retry("TagGadgetImage", func() error {
		var err error
		desc, err = tagGadgetImage(ctx, srcImage, dstImage)
		return err
	})

	return desc, err
}

func tagGadgetImage(ctx context.Context, srcImage, dstImage string) (*GadgetImageDesc, error) {
	src, err := normalizeImageName(srcImage)
	if err != nil {
		return nil, fmt.Errorf("normalizing src image: %w", err)
	}
	dst, err := normalizeImageName(dstImage)
	if err != nil {
		return nil, fmt.Errorf("normalizing dst image: %w", err)
	}

	ociStore, err := newLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	targetDescriptor, err := ociStore.Resolve(context.TODO(), src.String())
	if err != nil {
		// Error message not that helpful
		return nil, fmt.Errorf("resolving src: %w", err)
	}

	if err := ociStore.Tag(context.TODO(), targetDescriptor, dst.String()); err != nil {
		return nil, fmt.Errorf("tagging image: %w", err)
	}

	if err := ociStore.saveIndexWithLock(); err != nil {
		return nil, err
	}

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

// sortIndex sorts the manifest list in the index file and writes it back. This
// is done to be sure the index is deterministic and the generate tar file is
// the same.
func sortIndex(indexPath string) (*ocispec.Index, error) {
	file, err := os.ReadFile(indexPath)
	if err != nil {
		return nil, fmt.Errorf("reading index.json: %w", err)
	}

	var index ocispec.Index
	if err = json.Unmarshal(file, &index); err != nil {
		return nil, fmt.Errorf("unmarshalling index.json: %w", err)
	}

	slices.SortFunc(index.Manifests, func(a, b ocispec.Descriptor) int {
		return cmp.Compare(a.Digest.String(), b.Digest.String())
	})

	file, err = json.Marshal(index)
	if err != nil {
		return nil, fmt.Errorf("marshalling index.json: %w", err)
	}

	if err = os.WriteFile(indexPath, file, 0o600); err != nil {
		return nil, fmt.Errorf("writing index.json: %w", err)
	}

	return &index, nil
}

func ExportGadgetImages(ctx context.Context, dstFile string, images ...string) error {
	ociStore, err := newLocalOciStore()
	if err != nil {
		return fmt.Errorf("getting oci store: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", "gadget-export-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	dstStore, err := oci.New(tmpDir)
	if err != nil {
		return fmt.Errorf("creating oci storage: %w", err)
	}

	for _, image := range images {
		targetImage, err := normalizeImageName(image)
		if err != nil {
			return fmt.Errorf("normalizing image: %w", err)
		}
		desc, err := oras.Copy(ctx, ociStore, targetImage.String(), dstStore,
			targetImage.String(), oras.DefaultCopyOptions)
		if err != nil {
			return fmt.Errorf("copying image to remote repository: %w", err)
		}

		err = signatureverifier.ExportSigningInformation(ctx, ociStore, dstStore, desc)
		if errors.Is(err, errdef.ErrNotFound) {
			continue
		}
	}

	index, err := sortIndex(path.Join(tmpDir, "index.json"))
	if err != nil {
		return fmt.Errorf("reading index.json: %w", err)
	}

	// Set the time of the tar file to the creation time of the index. This
	// allows to have a deterministic tarball.
	var tarHeaderTime time.Time
	if index.Annotations != nil && index.Annotations[ocispec.AnnotationCreated] != "" {
		tarHeaderTime, err = time.Parse(time.RFC3339, index.Annotations[ocispec.AnnotationCreated])
		if err != nil {
			return fmt.Errorf("parsing created time: %w", err)
		}
	}

	if err := tarFolderToFile(tmpDir, dstFile, tarHeaderTime); err != nil {
		return fmt.Errorf("creating tar for gadget image: %w", err)
	}

	return nil
}

// ImportGadgetImages imports all the tagged gadget images from the src file.
func ImportGadgetImages(ctx context.Context, srcFile string) ([]string, error) {
	src, err := oci.NewFromTar(ctx, srcFile)
	if err != nil {
		return nil, fmt.Errorf("loading src bundle: %w", err)
	}

	ociStore, err := newLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	ret := []string{}

	err = src.Tags(ctx, "", func(tags []string) error {
		for _, tag := range tags {
			_, err := oras.Copy(ctx, src, tag, ociStore, tag, oras.DefaultCopyOptions)
			if err != nil {
				return fmt.Errorf("copying to local repository: %w", err)
			}

			if !strings.HasSuffix(tag, ".sig") {
				ret = append(ret, tag)
			}
		}
		return nil
	})

	if err := ociStore.saveIndexWithLock(); err != nil {
		return nil, err
	}

	return ret, err
}

// based on https://medium.com/@skdomino/taring-untaring-files-in-go-6b07cf56bc07
func tarFolderToFile(src, filePath string, headerTime time.Time) error {
	file, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("opening file: %w", err)
	}

	tw := tar.NewWriter(file)
	defer tw.Close()

	return filepath.Walk(src, func(file string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !fi.Mode().IsRegular() {
			return nil
		}

		header, err := tar.FileInfoHeader(fi, fi.Name())
		if err != nil {
			return err
		}

		header.ModTime = headerTime
		header.AccessTime = headerTime
		header.ChangeTime = headerTime

		// update the name to correctly reflect the desired destination when untaring
		header.Name = strings.TrimPrefix(strings.ReplaceAll(file, src, ""), string(filepath.Separator))

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		f, err := os.Open(file)
		if err != nil {
			return err
		}

		if _, err := io.Copy(tw, f); err != nil {
			return err
		}

		f.Close()

		return nil
	})
}

func getGadgetImageDescriptor(ctx context.Context, store *oci.Store, fullTag string) (*GadgetImageDesc, error) {
	parsed, err := reference.Parse(fullTag)
	if err != nil {
		return nil, fmt.Errorf("parsing image %q: %w", fullTag, err)
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
		return nil, fmt.Errorf("found tag %q but couldn't get a descriptor for it: %w", fullTag, err)
	}
	image.Digest = desc.Digest.String()

	manifest, err := getManifestForHost(ctx, store, fullTag)
	if err != nil {
		return nil, fmt.Errorf("getting manifest for %q: %w", fullTag, err)
	}

	image.Created = getTimeFromAnnotations(manifest.Annotations)

	return image, nil
}

func getGadgetImages(ctx context.Context, store *oci.Store) ([]*GadgetImageDesc, error) {
	images := []*GadgetImageDesc{}
	err := store.Tags(ctx, "", func(tags []string) error {
		for _, fullTag := range tags {
			image, err := getGadgetImageDescriptor(ctx, store, fullTag)
			if err != nil {
				// avoid printing warnings if the manifest is not found, it could be a signature tag
				if !errors.Is(err, errdef.ErrNotFound) {
					log.Warnf("getting gadget image descriptor for %s: %v", fullTag, err)
				}
				continue
			}

			images = append(images, image)
		}
		return nil
	})

	return images, err
}

// GetGadgetImages gets all the gadget images.
func GetGadgetImages(ctx context.Context) ([]*GadgetImageDesc, error) {
	ociStore, err := newLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	images, err := getGadgetImages(ctx, ociStore.Store)
	if err != nil {
		return nil, fmt.Errorf("listing all tags: %w", err)
	}

	for _, image := range images {
		image.Repository = strings.TrimPrefix(image.Repository, DefaultDomain+"/"+officialRepoPrefix)
	}

	return images, nil
}

func GetGadgetImageDesc(ctx context.Context, image string) (*GadgetImageDesc, error) {
	ociStore, err := newLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	targetImage, err := normalizeImageName(image)
	if err != nil {
		return nil, fmt.Errorf("normalizing image: %w", err)
	}

	fullName := targetImage.String()
	desc, err := getGadgetImageDescriptor(ctx, ociStore.Store, fullName)
	if err != nil {
		return nil, fmt.Errorf("getting gadget image descriptor: %w", err)
	}

	return desc, nil
}

// DeleteGadgetImage removes the given image.
func DeleteGadgetImage(ctx context.Context, image string) error {
	return retry("DeleteGadgetImage", func() error {
		return deleteGadgetImage(ctx, image)
	})
}

func deleteGadgetImage(ctx context.Context, image string) error {
	ociStore, err := newLocalOciStore()
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

	images, err := getGadgetImages(ctx, ociStore.Store)
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
			if err := ociStore.Untag(ctx, fullName); err != nil {
				return err
			}

			return ociStore.saveIndexWithLock()
		}
	}

	if err = ociStore.Delete(ctx, descriptor); err != nil {
		return err
	}

	if err := ociStore.saveIndexWithLock(); err != nil {
		return err
	}

	// TODO: GC() could race with other processes calling it a the same time.
	return ociStore.GC(ctx)
}

// SplitIGDomain splits a repository name to domain and remote-name.
// If no valid domain is found, the default domain is used. Repository name
// needs to be already validated before.
// Inspired on https://github.com/distribution/reference/blob/v0.5.0/normalize.go#L126
// TODO: Ideally we should use the upstream function but docker.io is hardcoded there
// https://github.com/distribution/reference/blob/v0.5.0/normalize.go#L31
func SplitIGDomain(name string) (domain, remainder string) {
	i := strings.IndexRune(name, '/')
	if i == -1 || (!strings.ContainsAny(name[:i], ".:") && name[:i] != localhost && strings.ToLower(name[:i]) == name[:i]) {
		domain, remainder = DefaultDomain, name
	} else {
		domain, remainder = name[:i], name[i+1:]
	}
	if domain == DefaultDomain && !strings.ContainsRune(remainder, '/') {
		remainder = officialRepoPrefix + remainder
	}
	return
}

func normalizeImageName(image string) (reference.Named, error) {
	// Use the default gadget's registry if no domain is specified.
	domain, remainer := SplitIGDomain(image)

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

	if len(authOptions.SecretBytes) != 0 {
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

	registryDomain := reference.Domain(image)
	insecure := slices.Contains(authOpts.InsecureRegistries, registryDomain)

	repo.PlainHTTP = insecure
	if !insecure {
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

func ensureImage(ctx context.Context, imageStore oras.Target, image string, imgOpts *ImageOptions, pullPolicy string) error {
	switch pullPolicy {
	case PullImageAlways:
		_, err := pullGadgetImageToStore(ctx, imageStore, image, &imgOpts.AuthOptions)
		if err != nil {
			return fmt.Errorf("pulling image (always) %q: %w", image, err)
		}
	case PullImageMissing:
		if err := pullIfNotExist(ctx, imageStore, &imgOpts.AuthOptions, image); err != nil {
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

	if len(imgOpts.AllowedGadgets) > 0 {
		found := false

		normalizedImage, err := normalizeImageName(image)
		if err != nil {
			return fmt.Errorf("normalizing image: %w", err)
		}

		imageStr := normalizedImage.String()

		desc, err := imageStore.Resolve(ctx, imageStr)
		if err != nil {
			return fmt.Errorf("resolving image %q on local registry: %w", imageStr, err)
		}

		imageDigest := normalizedImage.Name() + "@" + desc.Digest.String()

		for _, allowedGadget := range imgOpts.AllowedGadgets {
			// Check full match on digest or name
			if imageDigest == allowedGadget || imageStr == allowedGadget {
				found = true
				break
			}
			// Check prefix match
			if allowedGadget[len(allowedGadget)-1] == '*' {
				if strings.HasPrefix(imageStr, allowedGadget[:len(allowedGadget)-1]) {
					found = true
					break
				}
			}
		}

		if !found {
			return fmt.Errorf("%s is not part of allowed gadgets: %v", image, strings.Join(imgOpts.AllowedGadgets, ", "))
		}
	}

	if !imgOpts.VerifySignature {
		log.Warnf("gadget signature verification is disabled due to using corresponding option")

		return nil
	}

	imageRef, err := normalizeImageName(image)
	if err != nil {
		return fmt.Errorf("normalizing image name: %w", err)
	}

	repo, err := newRepository(imageRef, &imgOpts.AuthOptions)
	if err != nil {
		return fmt.Errorf("creating remote repository: %w", err)
	}

	err = signatureverifier.Verify(ctx, repo, imageStore, imageRef, imgOpts.VerifyOptions.VerifyOptions)
	if err != nil {
		return fmt.Errorf("verifying gadget signature %q: %w", image, err)
	}

	return nil
}

// EnsureImage ensures the image is present in the local store
func EnsureImage(ctx context.Context, image string, imgOpts *ImageOptions, pullPolicy string) error {
	return retry("EnsureImage", func() error {
		imageStore, err := newLocalOciStore()
		if err != nil {
			return fmt.Errorf("getting local oci store: %w", err)
		}

		if err := ensureImage(ctx, imageStore, image, imgOpts, pullPolicy); err != nil {
			return err
		}

		return imageStore.saveIndexWithLock()
	})
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

func GetManifestForHost(ctx context.Context, target oras.ReadOnlyTarget, image string) (*ocispec.Manifest, error) {
	if target == nil {
		var err error
		target, err = newLocalOciStore()
		if err != nil {
			return nil, fmt.Errorf("getting local oci store: %w", err)
		}
	}
	return getManifestForHost(ctx, target, image)
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

func GetContentFromDescriptor(ctx context.Context, target oras.ReadOnlyTarget, desc ocispec.Descriptor) (io.ReadCloser, error) {
	if target == nil {
		var err error
		target, err = newLocalOciStore()
		if err != nil {
			return nil, fmt.Errorf("getting local oci store: %w", err)
		}
	}
	reader, err := target.Fetch(ctx, desc)
	if err != nil {
		return nil, fmt.Errorf("fetching descriptor: %w", err)
	}
	return reader, nil
}

// ExtractSources retrieves the gadget source blob (if present) from the given image
// and extracts it (tar.gz) into destDir. It returns true if sources were found and extracted.
func ExtractSources(ctx context.Context, imageStore oras.Target, image string, destDir string, authOpts *AuthOptions, uid, gid int) (bool, error) {
	if imageStore == nil {
		// If no store is given, use the default store; we assume the image is available in that case
		ociStore, err := newLocalOciStore()
		if err != nil {
			return false, fmt.Errorf("getting oci store: %w", err)
		}
		imageStore = ociStore.Store
	} else {
		// If a store is given, we will pull the image
		_, err := pullGadgetImageToStore(ctx, imageStore, image, authOpts)
		if err != nil {
			return false, fmt.Errorf("pulling gadget image: %w", err)
		}
	}

	index, err := getIndex(ctx, imageStore, image)
	if err != nil {
		return false, fmt.Errorf("getting index: %w", err)
	}

	for _, desc := range index.Manifests {
		if desc.MediaType == sourceMediaType {
			reader, err := imageStore.Fetch(ctx, desc)
			if err != nil {
				return false, fmt.Errorf("fetching sources blob: %w", err)
			}
			defer reader.Close()
			if err := extractTarGz(reader, destDir, uid, gid); err != nil {
				return false, fmt.Errorf("extracting sources: %w", err)
			}
			return true, nil
		}
	}

	return false, nil
}

// extractTarGz extracts a gzip-compressed tar stream into destDir securely.
func extractTarGz(r io.Reader, destDir string, uid, gid int) error {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	cleanDest := filepath.Clean(destDir)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("reading tar: %w", err)
		}

		target := filepath.Join(cleanDest, hdr.Name)
		cleanTarget := filepath.Clean(target)
		// ensure target is within destDir
		if !strings.HasPrefix(cleanTarget+string(os.PathSeparator), cleanDest+string(os.PathSeparator)) && cleanTarget != cleanDest {
			return fmt.Errorf("invalid path in archive: %s", hdr.Name)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(cleanTarget, 0o755); err != nil {
				return fmt.Errorf("creating dir: %w", err)
			}
			if uid != -1 && gid != -1 {
				if err := os.Chown(cleanTarget, uid, gid); err != nil {
					return fmt.Errorf("setting uid/gid: %w", err)
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o755); err != nil {
				return fmt.Errorf("creating parent dir: %w", err)
			}
			f, err := os.OpenFile(cleanTarget, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, os.FileMode(hdr.Mode))
			if err != nil {
				return fmt.Errorf("creating file: %w", err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return fmt.Errorf("writing file: %w", err)
			}
			if uid != -1 && gid != -1 {
				if err := f.Chown(uid, gid); err != nil {
					return fmt.Errorf("setting uid/gid: %w", err)
				}
			}
			f.Close()
		case tar.TypeSymlink:
			// Create symlink only if it stays within destDir
			linkTarget := hdr.Linkname
			// For safety, do not allow absolute links
			if filepath.IsAbs(linkTarget) {
				return fmt.Errorf("absolute symlink not allowed: %s", hdr.Name)
			}
			finalLink := filepath.Join(filepath.Dir(cleanTarget), linkTarget)
			finalLink = filepath.Clean(finalLink)
			if !strings.HasPrefix(finalLink+string(os.PathSeparator), cleanDest+string(os.PathSeparator)) && finalLink != cleanDest {
				return fmt.Errorf("symlink escapes destination: %s -> %s", hdr.Name, linkTarget)
			}
			if err := os.MkdirAll(filepath.Dir(cleanTarget), 0o755); err != nil {
				return fmt.Errorf("creating parent dir: %w", err)
			}
			if err := os.Symlink(linkTarget, cleanTarget); err != nil {
				return fmt.Errorf("creating symlink: %w", err)
			}
			if uid != -1 && gid != -1 {
				if err := os.Chown(cleanTarget, uid, gid); err != nil {
					return fmt.Errorf("setting uid/gid: %w", err)
				}
			}
		default:
			// ignore other types
		}
	}
	return nil
}
