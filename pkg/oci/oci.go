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
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
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
	"github.com/sigstore/sigstore/pkg/signature"
	"github.com/sigstore/sigstore/pkg/signature/payload"
	log "github.com/sirupsen/logrus"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/content/oci"
	"oras.land/oras-go/v2/errdef"
	"oras.land/oras-go/v2/registry/remote"
	oras_auth "oras.land/oras-go/v2/registry/remote/auth"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

type AuthOptions struct {
	AuthFile    string
	SecretBytes []byte
	// InsecureRegistries is a list of registries that should be accessed over
	// plain HTTP.
	InsecureRegistries []string
	DisallowPulling    bool
}

type VerifyOptions struct {
	VerifyPublicKey bool
	PublicKeys      []string
}

type AllowedGadgetsOptions struct {
	AllowedGadgets []string
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

const (
	defaultDomain      = "ghcr.io"
	officialRepoPrefix = "inspektor-gadget/gadget/"
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
		_, err = oras.Copy(ctx, ociStore, targetImage.String(), dstStore,
			targetImage.String(), oras.DefaultCopyOptions)
		if err != nil {
			return fmt.Errorf("copying to remote repository: %w", err)
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

			ret = append(ret, tag)
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
				log.Warnf("getting gadget image descriptor for %s: %v", fullTag, err)
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
		image.Repository = strings.TrimPrefix(image.Repository, defaultDomain+"/"+officialRepoPrefix)
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

// splitIGDomain splits a repository name to domain and remote-name.
// If no valid domain is found, the default domain is used. Repository name
// needs to be already validated before.
// Inspired on https://github.com/distribution/reference/blob/v0.5.0/normalize.go#L126
// TODO: Ideally we should use the upstream function but docker.io is hardcoded there
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

func craftSignatureTag(digest string) (string, error) {
	// WARNING: cosign is considering changing the scheme for
	// publishing/retrieving sigstore bundles to/from an OCI registry, see:
	// https://sigstore.slack.com/archives/C0440BFT43H/p1712253122721879?thread_ts=1712238666.552719&cid=C0440BFT43H
	// https://github.com/sigstore/cosign/pull/3622
	parts := strings.Split(digest, ":")
	if len(parts) != 2 {
		return "", fmt.Errorf("wrong digest, expected two parts, got %d", len(parts))
	}

	return fmt.Sprintf("%s-%s.sig", parts[0], parts[1]), nil
}

func getSignature(ctx context.Context, repo *remote.Repository, signatureTag string) ([]byte, string, error) {
	_, signatureManifestBytes, err := oras.FetchBytes(ctx, repo, signatureTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, "", fmt.Errorf("getting signature bytes: %w", err)
	}

	signatureManifest := &ocispec.Manifest{}
	err = json.Unmarshal(signatureManifestBytes, signatureManifest)
	if err != nil {
		return nil, "", fmt.Errorf("decoding signature manifest: %w", err)
	}

	layers := signatureManifest.Layers
	expectedLen := 1
	layersLen := len(layers)
	if layersLen != expectedLen {
		return nil, "", fmt.Errorf("wrong number of signature manifest layers: expected %d, got %d", expectedLen, layersLen)
	}

	layer := layers[0]
	// Taken from:
	// https://github.com/sigstore/cosign/blob/e23dcd11f24b729f6ff9300ab7a61b09d71da12a/pkg/types/media.go#L28
	expectedMediaType := "application/vnd.dev.cosign.simplesigning.v1+json"
	if layer.MediaType != expectedMediaType {
		return nil, "", fmt.Errorf("wrong layer media type: expected %s, got %s", expectedMediaType, layer.MediaType)
	}

	signature, ok := layer.Annotations["dev.cosignproject.cosign/signature"]
	if !ok {
		return nil, "", fmt.Errorf("no signature in layer")
	}

	signatureBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return nil, "", fmt.Errorf("decoding signature: %w", err)
	}

	payloadTag := layer.Digest.String()

	return signatureBytes, payloadTag, nil
}

func getPayload(ctx context.Context, repo *remote.Repository, payloadTag string) ([]byte, error) {
	// The payload is stored as a blob, so we fetch bytes from the blob store and
	// not the manifest one.
	_, payloadBytes, err := oras.FetchBytes(ctx, repo.Blobs(), payloadTag, oras.DefaultFetchBytesOptions)
	if err != nil {
		return nil, fmt.Errorf("getting payload bytes: %w", err)
	}

	return payloadBytes, nil
}

func getImageDigest(ctx context.Context, store oras.Target, imageRef string) (string, error) {
	desc, err := store.Resolve(ctx, imageRef)
	if err != nil {
		return "", fmt.Errorf("resolving image %q: %w", imageRef, err)
	}

	return desc.Digest.String(), nil
}

func getSigningInformation(ctx context.Context, repo *remote.Repository, imageDigest string) ([]byte, []byte, error) {
	signatureTag, err := craftSignatureTag(imageDigest)
	if err != nil {
		return nil, nil, fmt.Errorf("crafting signature tag: %w", err)
	}

	signature, payloadTag, err := getSignature(ctx, repo, signatureTag)
	if err != nil {
		return nil, nil, fmt.Errorf("getting signature: %w", err)
	}

	payload, err := getPayload(ctx, repo, payloadTag)
	if err != nil {
		return nil, nil, fmt.Errorf("getting payload: %w", err)
	}

	return signature, payload, nil
}

func newVerifier(publicKey []byte) (signature.Verifier, error) {
	block, _ := pem.Decode(publicKey)
	if block == nil {
		return nil, fmt.Errorf("decoding public key to PEM blocks")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing public key: %w", err)
	}

	verifier, err := signature.LoadVerifier(pub, crypto.SHA256)
	if err != nil {
		return nil, fmt.Errorf("loading verifier: %w", err)
	}

	return verifier, nil
}

func checkPayloadImage(payloadBytes []byte, imageDigest string) error {
	payloadImage := &payload.SimpleContainerImage{}
	err := json.Unmarshal(payloadBytes, payloadImage)
	if err != nil {
		return fmt.Errorf("unmarshalling payload: %w", err)
	}

	if payloadImage.Critical.Image.DockerManifestDigest != imageDigest {
		return fmt.Errorf("payload digest does not correspond to image: expected %s, got %s", imageDigest, payloadImage.Critical.Image.DockerManifestDigest)
	}

	return nil
}

func verifyImage(ctx context.Context, imageStore oras.Target, image string, imgOpts *ImageOptions) error {
	imageRef, err := normalizeImageName(image)
	if err != nil {
		return fmt.Errorf("normalizing image name: %w", err)
	}

	imageDigest, err := getImageDigest(ctx, imageStore, imageRef.String())
	if err != nil {
		return fmt.Errorf("getting image digest: %w", err)
	}

	repo, err := newRepository(imageRef, &imgOpts.AuthOptions)
	if err != nil {
		return fmt.Errorf("creating repository: %w", err)
	}

	signatureBytes, payloadBytes, err := getSigningInformation(ctx, repo, imageDigest)
	if err != nil {
		return fmt.Errorf("getting signing information: %w", err)
	}

	verified := false
	var errs error
	for _, publicKey := range imgOpts.PublicKeys {
		verifier, err := newVerifier([]byte(publicKey))
		if err != nil {
			return fmt.Errorf("creating verifier for %s: %w", publicKey, err)
		}

		err = verifier.VerifySignature(bytes.NewReader(signatureBytes), bytes.NewReader(payloadBytes))
		if err == nil {
			verified = true

			break
		}

		errs = errors.Join(errs, err)
	}

	if !verified {
		return fmt.Errorf("the image was not signed by the provided keys: %w", errs)
	}

	// We should not read the payload before confirming it was signed, so let's
	// do this check once it was confirmed to be signed:
	// https://github.com/containers/image/blob/main/docs/containers-signature.5.md#the-cryptographic-signature
	err = checkPayloadImage(payloadBytes, imageDigest)
	if err != nil {
		return fmt.Errorf("checking payload image: %w", err)
	}

	return nil
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

	if !imgOpts.VerifyPublicKey {
		imgOpts.Logger.Warnf("image signature verification is disabled due to using corresponding option")

		return nil
	}

	err := verifyImage(ctx, imageStore, image, imgOpts)
	if err != nil {
		return fmt.Errorf("verifying image %q: %w", image, err)
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
