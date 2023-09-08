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

package image

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci_helper"
)

//go:embed build.sh
var buildScript []byte

const (
	DEFAULT_BUILDER_IMAGE = "ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder:latest"
)

type buildFile struct {
	EBPFProgram string `yaml:"ebpfprogram"`
	Definition  string `yaml:"definition"`
	CFlags      string `yaml:"cflags"`
	// TODO: custom build script
	// TODO: author, etc.
}

type cmdOpts struct {
	file         string
	image        string
	local        bool
	builderImage string
}

func NewBuildCmd() *cobra.Command {
	opts := &cmdOpts{}

	cmd := &cobra.Command{
		Use:          "build IMAGE",
		Short:        "Build a gadget image",
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected exactly one unnamed argument")
			}

			if opts.local && opts.builderImage != DEFAULT_BUILDER_IMAGE {
				return fmt.Errorf("--local and --builder-image cannot be used at the same time")
			}

			opts.image = args[0]

			return runBuild(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.file, "file", "f", "build.yaml", "path to build.yaml")
	cmd.Flags().BoolVarP(&opts.local, "local", "l", false, "build using local tools")
	cmd.Flags().StringVar(&opts.builderImage, "builder-image", DEFAULT_BUILDER_IMAGE, "builder image to use")

	return cmd
}

type imageIndexOpts struct {
	progAmd64FilePath  string
	progArm64FilePath  string
	definitionFilePath string
	image              string
}

func runBuild(opts *cmdOpts) error {
	conf := &buildFile{
		EBPFProgram: "program.bpf.c",
		Definition:  "definition.yaml",
	}

	b, err := os.ReadFile(opts.file)
	if err != nil && (opts.file != "build.yaml" || !errors.Is(err, os.ErrNotExist)) {
		return fmt.Errorf("reading build file: %w", err)
	} else if err == nil {
		if err := yaml.Unmarshal(b, conf); err != nil {
			return fmt.Errorf("unmarshal build.yaml: %w", err)
		}
	}

	// make a temp folder to store the build results
	tmpDir, err := os.MkdirTemp("", "gadget-build")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if opts.local {
		buildCmd := exec.Command(
			"/bin/sh", "-c",
			string(buildScript),
			"", // TODO: why is it needed?
			conf.EBPFProgram,
			tmpDir,
			conf.CFlags,
		)
		out, err := buildCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("build script: %w: %s", err, out)
		}
	} else {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}

		buildCmd := exec.Command(
			"docker", "run", "--rm",
			"-v", cwd+":/work",
			"-v", tmpDir+":/out",
			opts.builderImage,
			"/build.sh",
			"/work/"+conf.EBPFProgram,
			"/out",
			conf.CFlags,
		)
		out, err := buildCmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("build script: %w: %s", err, out)
		}
	}

	imageIndexOpts := &imageIndexOpts{
		image:              opts.image,
		definitionFilePath: conf.Definition,
		progArm64FilePath:  filepath.Join(tmpDir, "arm64.bpf.o"),
		progAmd64FilePath:  filepath.Join(tmpDir, "x86.bpf.o"),
	}

	ociStore, err := oci_helper.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	indexDesc, err := createImageIndex(ociStore, imageIndexOpts)
	if err != nil {
		return fmt.Errorf("create image index: %w", err)
	}

	targetImage, err := oci_helper.NormalizeImage(imageIndexOpts.image)
	if err != nil {
		return fmt.Errorf("normalize image: %w", err)
	}

	err = ociStore.Tag(context.TODO(), indexDesc, targetImage)
	if err != nil {
		return fmt.Errorf("tag manifest: %w", err)
	}

	fmt.Printf("Successfully built %s@%s\n", targetImage, indexDesc.Digest)
	return nil
}

func pushDescriptorIfNotExists(target oras.Target, desc ocispec.Descriptor, contentReader io.Reader) error {
	err := target.Push(context.TODO(), desc, contentReader)
	if err != nil && !errors.Is(err, errdef.ErrAlreadyExists) {
		return fmt.Errorf("push descriptor: %w", err)
	}
	return nil
}

func createEbpfDesc(target oras.Target, progFilePath string) (ocispec.Descriptor, error) {
	progBytes, err := os.ReadFile(progFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read eBPF program file: %w", err)
	}
	progDesc := content.NewDescriptorFromBytes("application/vnd.gadget.ebpf.program.v1+binary", progBytes)
	progDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle:       "program.o",
		ocispec.AnnotationAuthors:     "TODO: authors",
		ocispec.AnnotationDescription: "TODO: description",
	}
	err = pushDescriptorIfNotExists(target, progDesc, bytes.NewReader(progBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push eBPF program: %w", err)
	}

	return progDesc, nil
}

func createDefinitionDesc(target oras.Target, definitionFilePath string) (ocispec.Descriptor, error) {
	definitionBytes, err := os.ReadFile(definitionFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("read definition file: %w", err)
	}
	defDesc := content.NewDescriptorFromBytes("application/vnd.gadget.config.v1+yaml", definitionBytes)
	defDesc.Annotations = map[string]string{
		ocispec.AnnotationTitle: "config.yaml",
	}
	err = pushDescriptorIfNotExists(target, defDesc, bytes.NewReader(definitionBytes))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push definition file: %w", err)
	}
	return defDesc, nil
}

func createManifestForTarget(target oras.Target, definitionFilePath, progFilePath, arch string) (ocispec.Descriptor, error) {
	progDesc, err := createEbpfDesc(target, progFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("create and push eBPF descriptor: %w", err)
	}

	// Read the definition file into a byte array
	defDesc, err := createDefinitionDesc(target, definitionFilePath)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("create definition descriptor: %w", err)
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
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	manifestDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifestJson)
	manifestDesc.Platform = &ocispec.Platform{
		Architecture: arch,
		OS:           "linux",
	}

	exists, err := target.Exists(context.TODO(), manifestDesc)
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("check manifest exists: %w", err)
	}
	if exists {
		return manifestDesc, nil
	}
	err = pushDescriptorIfNotExists(target, manifestDesc, bytes.NewReader(manifestJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest: %w", err)
	}

	return manifestDesc, nil
}

func createImageIndex(target oras.Target, o *imageIndexOpts) (ocispec.Descriptor, error) {
	// Read the eBPF program files and push them to the memory store
	layers := []ocispec.Descriptor{}
	if o.progAmd64FilePath != "" {
		amd64ManifestDesc, err := createManifestForTarget(target, o.definitionFilePath, o.progAmd64FilePath, "amd64")
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("create amd64 manifest: %w", err)
		}
		layers = append(layers, amd64ManifestDesc)
	}
	if o.progArm64FilePath != "" {
		arm64ManifestDesc, err := createManifestForTarget(target, o.definitionFilePath, o.progArm64FilePath, "arm64")
		if err != nil {
			return ocispec.Descriptor{}, fmt.Errorf("create arm64 manifest: %w", err)
		}
		layers = append(layers, arm64ManifestDesc)
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
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexJson)
	err = pushDescriptorIfNotExists(target, indexDesc, bytes.NewReader(indexJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest index: %w", err)
	}
	return indexDesc, nil
}
