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
	"embed"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/moby/moby/pkg/jsonmessage"
	"github.com/spf13/cobra"
	"golang.org/x/term"
	"gopkg.in/yaml.v3"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

//go:embed helpers
var helpersFS embed.FS

// It can be overridden at build time
var builderImage = "ghcr.io/inspektor-gadget/ebpf-builder:latest"

const (
	DEFAULT_EBPF_SOURCE = "program.bpf.c"
	DEFAULT_WASM        = "" // Wasm is optional; unset by default
	DEFAULT_METADATA    = "gadget.yaml"
)

type buildFile struct {
	EBPFSource string `yaml:"ebpfsource"`
	Wasm       string `yaml:"wasm"`
	Metadata   string `yaml:"metadata"`
	CFlags     string `yaml:"cflags"`
}

type cmdOpts struct {
	path             string
	file             string
	fileChanged      bool
	image            string
	local            bool
	outputDir        string
	builderImage     string
	updateMetadata   bool
	validateMetadata bool
	btfgen           bool
	btfhubarchive    string
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

			return runBuild(cmd, opts)
		},
	}

	cmd.Flags().StringVarP(&opts.file, "file", "f", "build.yaml", "Path to build.yaml")
	cmd.Flags().BoolVarP(&opts.local, "local", "l", false, "Build using local tools")
	cmd.Flags().StringVarP(&opts.outputDir, "output", "o", "", "Path to a folder to store generated files while building")
	cmd.Flags().StringVarP(&opts.image, "tag", "t", "", "Name for the built image (format name:tag)")
	cmd.Flags().StringVar(&opts.builderImage, "builder-image", builderImage, "Builder image to use")
	cmd.Flags().BoolVar(&opts.updateMetadata, "update-metadata", false, "Update the metadata according to the eBPF code")
	cmd.Flags().BoolVar(&opts.validateMetadata, "validate-metadata", true, "Validate the metadata file before building the gadget image")

	cmd.Flags().BoolVar(&opts.btfgen, "btfgen", false, "Enable btfgen")
	cmd.Flags().StringVar(&opts.btfhubarchive, "btfhub-archive", "", "Path to the location of the btfhub-archive files")

	return cmd
}

func buildCmd(outputDir, ebpf, wasm, cflags, btfhubarchive string, btfgen bool) []string {
	cmd := []string{
		"make", "-f", filepath.Join(outputDir, "Makefile.build"),
		"-j", fmt.Sprintf("%d", runtime.NumCPU()),
		"EBPFSOURCE=" + ebpf,
		"WASM=" + wasm,
		"OUTPUTDIR=" + outputDir,
		"CFLAGS=" + cflags,
		"all",
	}

	if btfgen {
		cmd = append(cmd, "BTFHUB_ARCHIVE="+btfhubarchive)
		cmd = append(cmd, "btfgen")
	}

	return cmd
}

func runBuild(cmd *cobra.Command, opts *cmdOpts) error {
	conf := &buildFile{
		EBPFSource: DEFAULT_EBPF_SOURCE,
		Wasm:       DEFAULT_WASM,
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

	if opts.btfgen && opts.btfhubarchive == "" {
		return errors.New("btfgen requires --btfhub-archive")
	}

	if opts.btfgen {
		cmd.Printf("btfgen is enabled, building will take a while...\n")
	}

	if err := yaml.Unmarshal(buildContent, conf); err != nil {
		return fmt.Errorf("unmarshaling build.yaml: %w", err)
	}

	if opts.outputDir != "" {
		if _, err := os.Stat(opts.outputDir); err != nil {
			return err
		}
	} else {
		// make a temp folder to store the build results
		tmpDir, err := os.MkdirTemp("", "gadget-build-")
		if err != nil {
			return fmt.Errorf("creating temp dir: %w", err)
		}
		defer os.RemoveAll(tmpDir)

		opts.outputDir = tmpDir
	}

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

	if _, err := os.Stat(conf.EBPFSource); errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("source file %q not found", conf.EBPFSource)
	}

	// copy helper files
	files, err := helpersFS.ReadDir("helpers")
	if err != nil {
		return fmt.Errorf("reading helpers: %w", err)
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		data, err := helpersFS.ReadFile(filepath.Join("helpers", file.Name()))
		if err != nil {
			return fmt.Errorf("reading helper file: %w", err)
		}

		if err := os.WriteFile(filepath.Join(opts.outputDir, file.Name()), data, 0o600); err != nil {
			return fmt.Errorf("writing helper file: %w", err)
		}
	}

	if opts.local {
		cmd := buildCmd(opts.outputDir, conf.EBPFSource, conf.Wasm, conf.CFlags, opts.btfhubarchive, opts.btfgen)
		command := exec.Command(cmd[0], cmd[1:]...)
		if out, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("build script: %w: %s", err, out)
		}
	} else {
		if err := buildInContainer(opts, conf); err != nil {
			return err
		}
	}

	// TODO: make this configurable?
	archs := []string{oci.ArchAmd64, oci.ArchArm64}
	objectsPaths := map[string]*oci.ObjectPath{}

	for _, arch := range archs {
		obj := &oci.ObjectPath{
			EBPF: filepath.Join(opts.outputDir, arch+".bpf.o"),
		}

		// TODO: the same wasm file is provided for all architectures. Should we allow per-arch
		// wasm files?
		if strings.HasSuffix(conf.Wasm, ".wasm") {
			// User provided an already-built wasm file
			obj.Wasm = conf.Wasm
		} else if conf.Wasm != "" {
			// User provided a source file to build wasm from
			obj.Wasm = filepath.Join(opts.outputDir, "program.wasm")
		}

		if opts.btfgen {
			archClean := arch
			if arch == oci.ArchAmd64 {
				archClean = "x86_64"
			}

			obj.Btfgen = filepath.Join(opts.outputDir, fmt.Sprintf("btfs-%s.tar.gz", archClean))
		}

		objectsPaths[arch] = obj
	}

	buildOpts := &oci.BuildGadgetImageOpts{
		EBPFSourcePath:   conf.EBPFSource,
		ObjectPaths:      objectsPaths,
		MetadataPath:     conf.Metadata,
		UpdateMetadata:   opts.updateMetadata,
		ValidateMetadata: opts.validateMetadata,
	}

	if sourceDateEpoch, ok := os.LookupEnv("SOURCE_DATE_EPOCH"); ok {
		sde, err := strconv.ParseInt(sourceDateEpoch, 10, 64)
		if err != nil {
			return fmt.Errorf("invalid SOURCE_DATE_EPOCH: %w", err)
		}
		buildOpts.CreatedDate = time.Unix(sde, 0).UTC().Format(time.RFC3339)
	} else {
		buildOpts.CreatedDate = time.Now().Format(time.RFC3339)
	}

	desc, err := oci.BuildGadgetImage(context.TODO(), buildOpts, opts.image)
	if err != nil {
		return err
	}

	cmd.Printf("Successfully built %s\n", desc.String())

	return nil
}

func ensureBuilderImage(ctx context.Context, cli *client.Client, builderImage string) error {
	f := filters.NewArgs()
	f.Add("reference", builderImage)

	// For :latest we always want to have the newest image that is available upstream
	if !strings.HasSuffix(builderImage, ":latest") {
		images, err := cli.ImageList(ctx, image.ListOptions{Filters: f})
		if err != nil {
			return fmt.Errorf("listing images: %w", err)
		}

		for _, img := range images {
			for _, tag := range img.RepoTags {
				if tag == builderImage {
					return nil
				}
			}
		}
	}

	fmt.Printf("Pulling builder image %s\n", builderImage)
	reader, err := cli.ImagePull(ctx, builderImage, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("pulling builder image: %w", err)
	}
	defer reader.Close()

	out := os.Stdout
	outFd := out.Fd()
	isTTY := term.IsTerminal(int(outFd))
	return jsonmessage.DisplayJSONMessagesStream(reader, out, outFd, isTTY, nil)
}

func buildInContainer(opts *cmdOpts, conf *buildFile) error {
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

	if err := ensureBuilderImage(ctx, cli, opts.builderImage); err != nil {
		return err
	}

	// where the gadget source code is mounted in the container
	gadgetSourcePath := "/work"
	pathHost := cwd

	inspektorGadetSrcPath := os.Getenv("IG_SOURCE_PATH")
	if inspektorGadetSrcPath != "" {
		pathHost = inspektorGadetSrcPath
		// find the gadget relative path to the inspektor-gadget source
		if !strings.HasPrefix(cwd, inspektorGadetSrcPath) {
			return fmt.Errorf("the current directory %q is not under the inspektor-gadget source path %q", cwd, inspektorGadetSrcPath)
		}
		gadgetRelativePath := strings.TrimPrefix(cwd, inspektorGadetSrcPath)
		gadgetSourcePath = filepath.Join("/work", gadgetRelativePath)

		// use in-tree headers too
		conf.CFlags += " -I /work/include/"
	}

	wasmFullPath := ""
	if conf.Wasm != "" {
		wasmFullPath = filepath.Join(gadgetSourcePath, conf.Wasm)
	}

	cmd := buildCmd("/out", filepath.Join(gadgetSourcePath, conf.EBPFSource),
		wasmFullPath, conf.CFlags, "/btfhub-archive", opts.btfgen)

	mounts := []mount.Mount{
		{
			Type:     mount.TypeBind,
			Target:   "/work",
			Source:   pathHost,
			ReadOnly: true,
		},
		{
			Type:   mount.TypeBind,
			Target: "/out",
			Source: opts.outputDir,
		},
	}

	if opts.btfgen {
		mounts = append(mounts, mount.Mount{
			Type:   mount.TypeBind,
			Target: "/btfhub-archive",
			Source: opts.btfhubarchive,
		})
	}

	resp, err := cli.ContainerCreate(
		ctx,
		&container.Config{
			Image:      opts.builderImage,
			Cmd:        cmd,
			WorkingDir: gadgetSourcePath,
			User:       fmt.Sprintf("%d:%d", os.Getuid(), os.Getgid()),
		},
		&container.HostConfig{
			Mounts: mounts,
		},
		nil, nil, "",
	)
	if err != nil {
		return fmt.Errorf("creating builder container: %w", err)
	}
	defer func() {
		if err := cli.ContainerRemove(ctx, resp.ID, container.RemoveOptions{}); err != nil {
			fmt.Printf("Failed to remove builder container: %s\n", err)
		}
	}()

	if err := cli.ContainerStart(ctx, resp.ID, container.StartOptions{}); err != nil {
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
		opts := container.LogsOptions{ShowStdout: true, ShowStderr: true}
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
