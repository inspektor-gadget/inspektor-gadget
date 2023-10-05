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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/docker/distribution/reference"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

const (
	ArchAmd64 = "amd64"
	ArchArm64 = "arm64"
)

const (
	eBPFObjectMediaType = "application/vnd.gadget.ebpf.program.v1+binary"
	metadataMediaType   = "application/vnd.gadget.config.v1+yaml"
)

type BuildGadgetImageOpts struct {
	// Source path of the eBPF program. Currently it's not used for compilation purposes
	EBPFSourcePath string
	// List of eBPF objects to include in the image. The key is the architecture and the value
	// is the path to the eBPF object.
	EBPFObjectPaths map[string]string
	// Path to the metadata file.
	MetadataPath string
	// If true, the metadata is updated to follow changes in the eBPF objects.
	UpdateMetadata bool
	// If true, the metadata is validated before creating the image.
	ValidateMetadata bool
}

// BuildGadgetImage creates an OCI image with the objects provided in opts. The image parameter in
// the "name:tag" format is used to name and tag the created image. If it's empty the image is not
// named.
func BuildGadgetImage(ctx context.Context, opts *BuildGadgetImageOpts, image string) (*GadgetImageDesc, error) {
	ociStore, err := getLocalOciStore()
	if err != nil {
		return nil, fmt.Errorf("getting oci store: %w", err)
	}

	if opts.UpdateMetadata {
		if err := createOrUpdateMetadataFile(ctx, opts); err != nil {
			return nil, fmt.Errorf("updating metadata file: %w", err)
		}
	}

	if opts.ValidateMetadata {
		if err := validateMetadataFile(ctx, opts); err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("validating metadata file: %w", err)
		}
	}

	indexDesc, err := createImageIndex(ctx, ociStore, opts)
	if err != nil {
		return nil, fmt.Errorf("creating image index: %w", err)
	}

	imageDesc := &GadgetImageDesc{
		Digest: indexDesc.Digest.String(),
	}

	if image != "" {
		targetImage, err := normalizeImageName(image)
		if err != nil {
			return nil, fmt.Errorf("normalizing image: %w", err)
		}

		err = ociStore.Tag(ctx, indexDesc, targetImage.String())
		if err != nil {
			return nil, fmt.Errorf("tagging manifest: %w", err)
		}

		imageDesc.Repository = targetImage.Name()
		if ref, ok := targetImage.(reference.Tagged); ok {
			imageDesc.Tag = ref.Tag()
		}
	}

	return imageDesc, nil
}

func pushDescriptorIfNotExists(ctx context.Context, target oras.Target, desc ocispec.Descriptor, contentReader io.Reader) error {
	err := target.Push(ctx, desc, contentReader)
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return fmt.Errorf("pushing descriptor: %w", err)
	}
	return nil
}

func createEbpfProgramDesc(ctx context.Context, target oras.Target, progFilePath string) (ocispec.Descriptor, error) {
	progBytes, err := os.ReadFile(progFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading eBPF program file: %w", err)
	}
	progDesc := content.NewDescriptorFromBytes(eBPFObjectMediaType, progBytes)
	progDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle:       "program.o",
		ocispec.AnnotationAuthors:     "TODO: authors",
		ocispec.AnnotationDescription: "TODO: description",
	}
	err = pushDescriptorIfNotExists(ctx, target, progDesc, bytes.NewReader(progBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing eBPF program: %w", err)
	}

	return progDesc, nil
}

func createMetadataDesc(ctx context.Context, target oras.Target, metadataFilePath string) (ocispec.Descriptor, error) {
	metadataBytes, err := os.ReadFile(metadataFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading metadata file: %w", err)
	}
	defDesc := content.NewDescriptorFromBytes(metadataMediaType, metadataBytes)
	defDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle: "config.yaml",
	}
	err = pushDescriptorIfNotExists(ctx, target, defDesc, bytes.NewReader(metadataBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing metadata file: %w", err)
	}
	return defDesc, nil
}

func createManifestForTarget(ctx context.Context, target oras.Target, metadataFilePath, progFilePath, arch string) (ocispec.Descriptor, error) {
	progDesc, err := createEbpfProgramDesc(ctx, target, progFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("creating and pushing eBPF descriptor: %w", err)
	}

	var defDesc ocispec.Descriptor

	if _, err := os.Stat(metadataFilePath); err == nil {
		// Read the metadata file into a byte array
		defDesc, err = createMetadataDesc(ctx, target, metadataFilePath)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating metadata descriptor: %w", err)
		}
	}

	// Create the manifest which combines everything and push it to the memory store
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2, // historical value. does not pertain to OCI or docker version
		},
		Config: defDesc,
		Layers: []ocispec.Descriptor{progDesc},
	}
	manifestJson, err := json.Marshal(manifest)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshalling manifest: %w", err)
	}
	manifestDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifestJson)
	manifestDesc.Platform = &ocispec.Platform{
		Architecture: arch,
		OS:           "linux",
	}

	exists, err := target.Exists(ctx, manifestDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("checking if manifest exists: %w", err)
	}
	if exists {
		return manifestDesc, nil
	}
	err = pushDescriptorIfNotExists(ctx, target, manifestDesc, bytes.NewReader(manifestJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing manifest: %w", err)
	}

	return manifestDesc, nil
}

func createImageIndex(ctx context.Context, target oras.Target, o *BuildGadgetImageOpts) (ocispec.Descriptor, error) {
	// Read the eBPF program files and push them to the memory store
	layers := []ocispec.Descriptor{}

	for arch, path := range o.EBPFObjectPaths {
		manifestDesc, err := createManifestForTarget(ctx, target, o.MetadataPath, path, arch)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating %s manifest: %w", arch, err)
		}
		layers = append(layers, manifestDesc)
	}

	// Create the index which combines the architectures and push it to the memory store
	index := ocispec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2, // historical value. does not pertain to OCI or docker version
		},
		MediaType: ocispec.MediaTypeImageIndex,
		Manifests: layers,
	}
	indexJson, err := json.Marshal(index)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshalling manifest: %w", err)
	}
	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexJson)
	err = pushDescriptorIfNotExists(ctx, target, indexDesc, bytes.NewReader(indexJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing manifest index: %w", err)
	}
	return indexDesc, nil
}
