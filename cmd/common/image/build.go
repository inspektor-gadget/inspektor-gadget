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
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

//go:embed Makefile.build
var makefile []byte

// It can be overridden at build time
var builderImage = "ghcr.io/inspektor-gadget/ebpf-builder:latest"

const (
	DEFAULT_EBPF_SOURCE = "program.bpf.c"
	DEFAULT_METADATA    = "gadget.yaml"
)

type buildFile struct {
	EBPFSource string `yaml:"ebpfsource"`
	Metadata   string `yaml:"metadata"`
	CFlags     string `yaml:"cflags"`
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
			if opts.local && opts.builderImage != builderImage {
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
	cmd.Flags().StringVar(&opts.builderImage, "builder-image", builderImage, "Builder image to use")

	return cmd
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
		return fmt.Errorf("unmarshaling build.yaml: %w", err)
	}

	// make a temp folder to store the build results
	tmpDir, err := os.MkdirTemp("", "gadget-build-")
	if err != nil {
		return fmt.Errorf("creating temp dir: %w", err)
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

	buildOpts := &oci.BuildGadgetImageOpts{
		EBPFObjectPaths: map[string]string{
			oci.ArchAmd64: filepath.Join(tmpDir, oci.ArchAmd64+".bpf.o"),
			oci.ArchArm64: filepath.Join(tmpDir, oci.ArchArm64+".bpf.o"),
		},
		MetadataPath: conf.Metadata,
	}

	desc, err := oci.BuildGadgetImage(context.TODO(), buildOpts, opts.image)
	if err != nil {
		return err
	}

	fmt.Printf("Successfully built %s\n", desc.String())

	return nil
}

func buildLocal(opts *cmdOpts, conf *buildFile, output string) error {
	makefilePath := filepath.Join(output, "Makefile")
	if err := os.WriteFile(makefilePath, makefile, 0o644); err != nil {
		return fmt.Errorf("writing Makefile: %w", err)
	}

	buildCmd := exec.Command(
		"make", "-f", makefilePath,
		"-j", fmt.Sprintf("%d", runtime.NumCPU()),
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
		fmt.Printf("Pulling builder image %s. It could take few minutes.\n", opts.builderImage)
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
				"make", "-f", "/Makefile", "-j", fmt.Sprintf("%d", runtime.NumCPU()),
				"EBPFSOURCE=" + filepath.Join("/work", conf.EBPFSource),
				"OUTPUTDIR=/out",
				"CFLAGS=" + conf.CFlags,
			},
			User: fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		},
		&container.HostConfig{
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
	defer func() {
		if err := cli.ContainerRemove(ctx, resp.ID, types.ContainerRemoveOptions{}); err != nil {
			fmt.Printf("Failed to remove builder container: %s\n", err)
		}
	}()

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
