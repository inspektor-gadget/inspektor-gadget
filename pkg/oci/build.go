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
	"slices"

	"github.com/distribution/reference"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"gopkg.in/yaml.v2"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

const (
	ArchAmd64 = "amd64"
	ArchArm64 = "arm64"
	ArchWasm  = "wasm"
)

const (
	artifactType        = "application/vnd.gadget.v1+binary"
	eBPFObjectMediaType = "application/vnd.gadget.ebpf.program.v1+binary"
	wasmObjectMediaType = "application/vnd.gadget.wasm.program.v1+binary"
	btfgenMediaType     = "application/vnd.gadget.btfgen.v1+binary"
	metadataMediaType   = "application/vnd.gadget.config.v1+yaml"
)

type ObjectPath struct {
	// Path to the EBPF object
	EBPF string
	// Optional path to the Wasm file
	Wasm string
	// Optional path to tarball containing BTF files generated with btfgen
	Btfgen string
}

type BuildGadgetImageOpts struct {
	// Source path of the eBPF program. Currently it's not used for compilation purposes
	EBPFSourcePath string
	// List of eBPF objects to include in the image. The key is the architecture and the value
	// are the paths to the objects.
	ObjectPaths map[string]*ObjectPath
	// Path to the metadata file.
	MetadataPath string
	// If true, the metadata is updated to follow changes in the eBPF objects.
	UpdateMetadata bool
	// If true, the metadata is validated before creating the image.
	ValidateMetadata bool
	// Date and time on which the image is built (date-time string as defined by RFC 3339).
	CreatedDate string
}

// BuildGadgetImage creates an OCI image with the objects provided in opts. The image parameter in
// the "name:tag" format is used to name and tag the created image. If it's empty the image is not
// named.
func BuildGadgetImage(ctx context.Context, opts *BuildGadgetImageOpts, image string) (*GadgetImageDesc, error) {
	ociStore, err := GetLocalOciStore()
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

	if err := fixGeneratedFilesOwner(opts); err != nil {
		return nil, fmt.Errorf("fixing generated files owner: %w", err)
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

func createLayerDesc(ctx context.Context, target oras.Target, progFilePath, mediaType string) (ocispec.Descriptor, error) {
	progBytes, err := os.ReadFile(progFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading eBPF program file: %w", err)
	}
	progDesc := content.NewDescriptorFromBytes(mediaType, progBytes)

	err = pushDescriptorIfNotExists(ctx, target, progDesc, bytes.NewReader(progBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing %q layer: %w", mediaType, err)
	}

	return progDesc, nil
}

func annotationsFromMetadata(metadataBytes []byte) (map[string]string, error) {
	metadata := &metadatav1.GadgetMetadata{}
	if err := yaml.NewDecoder(bytes.NewReader(metadataBytes)).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("decoding metadata file: %w", err)
	}

	// Suggested annotations for the OCI image
	// https://github.com/opencontainers/image-spec/blob/main/annotations.md#pre-defined-annotation-keys
	annotations := map[string]string{
		ocispec.AnnotationTitle:         metadata.Name,
		ocispec.AnnotationDescription:   metadata.Description,
		ocispec.AnnotationURL:           metadata.HomepageURL,
		ocispec.AnnotationDocumentation: metadata.DocumentationURL,
		ocispec.AnnotationSource:        metadata.SourceURL,
	}

	for k, v := range metadata.Annotations {
		annotations[k] = v
	}
	return annotations, nil
}

func createMetadataDesc(ctx context.Context, target oras.Target, metadataFilePath string) (ocispec.Descriptor, error) {
	metadataBytes, err := os.ReadFile(metadataFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading metadata file: %w", err)
	}
	defDesc := content.NewDescriptorFromBytes(metadataMediaType, metadataBytes)
	defDesc.Annotations, err = annotationsFromMetadata(metadataBytes)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("reading annotations from metadata file: %w", err)
	}

	err = pushDescriptorIfNotExists(ctx, target, defDesc, bytes.NewReader(metadataBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing metadata file: %w", err)
	}
	return defDesc, nil
}

func createEmptyDesc(ctx context.Context, target oras.Target) (ocispec.Descriptor, error) {
	emptyDesc := ocispec.DescriptorEmptyJSON
	err := pushDescriptorIfNotExists(ctx, target, emptyDesc, bytes.NewReader(emptyDesc.Data))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing empty descriptor: %w", err)
	}
	return emptyDesc, nil
}

func createManifestForTarget(ctx context.Context, target oras.Target, metadataFilePath, arch string, paths *ObjectPath, createdDate string) (ocispec.Descriptor, error) {
	layerDescs := []ocispec.Descriptor{}

	progDesc, err := createLayerDesc(ctx, target, paths.EBPF, eBPFObjectMediaType)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("creating and pushing eBPF descriptor: %w", err)
	}
	layerDescs = append(layerDescs, progDesc)

	if paths.Wasm != "" {
		wasmDesc, err := createLayerDesc(ctx, target, paths.Wasm, wasmObjectMediaType)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating and pushing wasm descriptor: %w", err)
		}
		layerDescs = append(layerDescs, wasmDesc)
	}

	if paths.Btfgen != "" {
		btfDesc, err := createLayerDesc(ctx, target, paths.Btfgen, btfgenMediaType)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating and pushing btfgen descriptor: %w", err)
		}
		layerDescs = append(layerDescs, btfDesc)
	}

	var defDesc ocispec.Descriptor

	if _, err := os.Stat(metadataFilePath); err == nil {
		// Read the metadata file into a byte array
		defDesc, err = createMetadataDesc(ctx, target, metadataFilePath)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating metadata descriptor: %w", err)
		}
		defDesc.Annotations[ocispec.AnnotationCreated] = createdDate
	} else {
		// Create an empty descriptor
		defDesc, err = createEmptyDesc(ctx, target)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating empty descriptor: %w", err)
		}

		// Even without metadata, we can still set some annotations
		defDesc.Annotations = map[string]string{
			ocispec.AnnotationCreated: createdDate,
		}
	}

	// Create the manifest which combines everything and push it to the memory store
	manifest := ocispec.Manifest{
		Versioned: specs.Versioned{
			SchemaVersion: 2, // historical value. does not pertain to OCI or docker version
		},
		Config:       defDesc,
		Layers:       layerDescs,
		Annotations:  defDesc.Annotations,
		ArtifactType: artifactType,
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
	manifestDesc.Annotations = manifest.Annotations

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

	archs := make([]string, 0, len(o.ObjectPaths))
	for k := range o.ObjectPaths {
		archs = append(archs, k)
	}

	// Sort the keys to ensure the order of the layers is deterministic
	slices.Sort(archs)

	for _, arch := range archs {
		paths := o.ObjectPaths[arch]
		manifestDesc, err := createManifestForTarget(ctx, target, o.MetadataPath, arch, paths, o.CreatedDate)
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("creating %s manifest: %w", arch, err)
		}
		layers = append(layers, manifestDesc)
	}

	if len(layers) == 0 {
		return ocispec.Descriptor{}, fmt.Errorf("no eBPF objects found")
	}

	// Create the index which combines the architectures and push it to the memory store
	index := ocispec.Index{
		Versioned: specs.Versioned{
			SchemaVersion: 2, // historical value. does not pertain to OCI or docker version
		},
		MediaType:   ocispec.MediaTypeImageIndex,
		Manifests:   layers,
		Annotations: layers[0].Annotations,
	}
	indexJson, err := json.Marshal(index)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("marshalling manifest: %w", err)
	}
	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexJson)
	indexDesc.Annotations = index.Annotations

	err = pushDescriptorIfNotExists(ctx, target, indexDesc, bytes.NewReader(indexJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("pushing manifest index: %w", err)
	}
	return indexDesc, nil
}
