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

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/opencontainers/image-spec/specs-go"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

//go:embed Makefile.build
var makefile []byte

const (
	DEFAULT_BUILDER_IMAGE = "ghcr.io/inspektor-gadget/inspektor-gadget-ebpf-builder:latest"
	DEFAULT_EBPF_SOURCE   = "program.bpf.c"
	DEFAULT_METADATA      = "gadget.yaml"
	ARCH_AMD64            = "amd64"
	ARCH_ARM64            = "arm64"
)

type buildFile struct {
	EBPFSource string `yaml:"ebpfsource"`
	Metadata   string `yaml:"metadata"`
	CFlags     string `yaml:"cflags"`
	// TODO: custom build script
	// TODO: author, etc.
}

type cmdOpts struct {
	path         string
	file         string
	fileChanged  bool
	image        string
	local        bool
	builderImage string
}

func NewBuildCmd() *cobra.Command {
	opts := &cmdOpts{}

	cmd := &cobra.Command{
		Use:          "build PATH",
		Short:        "Build a gadget image",
		SilenceUsage: true,
		Args:         cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if opts.local && opts.builderImage != DEFAULT_BUILDER_IMAGE {
				return fmt.Errorf("--local and --builder-image cannot be used at the same time")
			}

			fFlag := cmd.Flags().Lookup("file")
			opts.fileChanged = fFlag.Changed

			opts.path = args[0]

			return runBuild(opts)
		},
	}

	cmd.Flags().StringVarP(&opts.file, "file", "f", "build.yaml", "Path to build.yaml")
	cmd.Flags().BoolVarP(&opts.local, "local", "l", false, "Build using local tools")
	cmd.Flags().StringVarP(&opts.image, "tag", "t", "", "Name for the built image (format name:tag)")
	cmd.Flags().StringVar(&opts.builderImage, "builder-image", DEFAULT_BUILDER_IMAGE, "Builder image to use")

	return cmd
}

type imageIndexOpts struct {
	// key is the architecture, value the path
	progPaths    map[string]string
	metadataPath string
	image        string
}

func runBuild(opts *cmdOpts) error {
	conf := &buildFile{
		EBPFSource: DEFAULT_EBPF_SOURCE,
		Metadata:   DEFAULT_METADATA,
	}

	var buildContent []byte
	var err error

	if opts.fileChanged {
		buildContent, err = os.ReadFile(opts.file)
		if err != nil {
			return fmt.Errorf("reading build file: %w", err)
		}
	} else {
		// The user specified the path but not the file. Use the default file build.yaml
		buildContent, err = os.ReadFile(filepath.Join(opts.path, opts.file))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("reading build file: %w", err)
		}
	}

	if err := yaml.Unmarshal(buildContent, conf); err != nil {
		return fmt.Errorf("unmarshal build.yaml: %w", err)
	}

	// make a temp folder to store the build results
	tmpDir, err := os.MkdirTemp("", "gadget-build-")
	if err != nil {
		return fmt.Errorf("create temp dir: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	if opts.path != "." {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("getting current directory: %w", err)
		}
		defer os.Chdir(cwd)

		if err := os.Chdir(opts.path); err != nil {
			return fmt.Errorf("changing directory: %w", err)
		}
	}

	if opts.local {
		if err := buildLocal(opts, conf, tmpDir); err != nil {
			return err
		}
	} else {
		if err := buildInContainer(opts, conf, tmpDir); err != nil {
			return err
		}
	}

	imageIndexOpts := &imageIndexOpts{
		image:        opts.image,
		metadataPath: conf.Metadata,
		progPaths: map[string]string{
			ARCH_AMD64: filepath.Join(tmpDir, ARCH_AMD64+".bpf.o"),
			ARCH_ARM64: filepath.Join(tmpDir, ARCH_ARM64+".bpf.o"),
		},
	}

	ociStore, err := oci.GetLocalOciStore()
	if err != nil {
		return fmt.Errorf("get oci store: %w", err)
	}

	indexDesc, err := createImageIndex(ociStore, imageIndexOpts)
	if err != nil {
		return fmt.Errorf("create image index: %w", err)
	}

	if imageIndexOpts.image != "" {
		targetImage, err := oci.NormalizeImage(imageIndexOpts.image)
		if err != nil {
			return fmt.Errorf("normalize image: %w", err)
		}

		err = ociStore.Tag(context.TODO(), indexDesc, targetImage)
		if err != nil {
			return fmt.Errorf("tag manifest: %w", err)
		}
		fmt.Printf("Successfully built %s@%s\n", targetImage, indexDesc.Digest)
	} else {
		fmt.Printf("Successfully built %s\n", indexDesc.Digest)
	}

	return nil
}

func buildLocal(opts *cmdOpts, conf *buildFile, output string) error {
	makefilePath := filepath.Join(output, "Makefile")
	if err := os.WriteFile(makefilePath, makefile, 0o644); err != nil {
		return fmt.Errorf("writing Makefile: %w", err)
	}

	buildCmd := exec.Command(
		"make", "-f", makefilePath, "-j", "2",
		"EBPFSOURCE="+conf.EBPFSource,
		"OUTPUTDIR="+output,
		"CFLAGS="+conf.CFlags,
	)
	if out, err := buildCmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build script: %w: %s", err, out)
	}

	return nil
}

func buildInContainer(opts *cmdOpts, conf *buildFile, output string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("getting current directory: %w", err)
	}

	ctx := context.TODO()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("creating docker client: %w", err)
	}
	defer cli.Close()

	f := filters.NewArgs()
	f.Add("reference", opts.builderImage)

	images, err := cli.ImageList(ctx, types.ImageListOptions{Filters: f})
	if err != nil {
		return fmt.Errorf("listing images: %w", err)
	}

	var found bool

	for _, img := range images {
		for _, tag := range img.RepoTags {
			if tag == opts.builderImage {
				found = true
				break
			}
		}

		if found {
			break
		}
	}

	if !found {
		fmt.Printf("Pulling builder image %s\n", opts.builderImage)
		reader, err := cli.ImagePull(ctx, opts.builderImage, types.ImagePullOptions{})
		if err != nil {
			return fmt.Errorf("pulling builder image: %w", err)
		}
		io.Copy(io.Discard, reader)
		reader.Close()
	}

	resp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image: opts.builderImage,
			Cmd: []string{
				"make", "-f", "/Makefile", "-j", "2",
				"EBPFSOURCE=" + filepath.Join("/work", conf.EBPFSource),
				"OUTPUTDIR=/out",
				"CFLAGS=" + conf.CFlags,
			},
		},
		&container.HostConfig{
			AutoRemove: true,
			Mounts: []mount.Mount{
				{
					Type:     mount.TypeBind,
					Target:   "/work",
					Source:   cwd,
					ReadOnly: true,
				},
				{
					Type:   mount.TypeBind,
					Target: "/out",
					Source: output,
				},
			},
		},
		nil, nil, "",
	)
	if err != nil {
		return fmt.Errorf("creating builder container: %w", err)
	}

	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		return fmt.Errorf("starting builder container: %w", err)
	}

	var status container.WaitResponse

	statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
	select {
	case err := <-errCh:
		if err != nil {
			return fmt.Errorf("waiting for builder container: %w", err)
		}
	case status = <-statusCh:
	}

	if status.StatusCode != 0 || common.Verbose {
		opts := types.ContainerLogsOptions{ShowStdout: true, ShowStderr: true}
		out, err := cli.ContainerLogs(ctx, resp.ID, opts)
		if err != nil {
			return fmt.Errorf("getting builder container logs: %w", err)
		}

		fmt.Printf("Builder container logs start:\n")
		stdcopy.StdCopy(os.Stdout, os.Stderr, out)
		fmt.Printf("Builder container logs end\n")
	}

	if status.StatusCode != 0 {
		return fmt.Errorf("builder container exited with status %d", status.StatusCode)
	}

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

	for arch, path := range o.progPaths {
		manifestDesc, err := createManifestForTarget(target, o.metadataPath, path, arch)
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
		return ocispec.Descriptor{}, fmt.Errorf("marshal manifest: %w", err)
	}
	indexDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageIndex, indexJson)
	err = pushDescriptorIfNotExists(target, indexDesc, bytes.NewReader(indexJson))
	if err != nil {
		return ocispec.Descriptor{}, fmt.Errorf("push manifest index: %w", err)
	}
	return indexDesc, nil
}
