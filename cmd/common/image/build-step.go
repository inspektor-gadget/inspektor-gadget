// Copyright 2026 The Inspektor Gadget authors
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
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/oci"
)

type buildStep struct {
	opts       buildOptions
	targetArch string
	run        func(runner commandRunner) error
}

var goArchToKernelArch = map[string]string{
	"amd64": "x86_64",
	"arm64": "aarch64",
}

func translateArch(arch string) string {
	if arch == oci.ArchAmd64 {
		return "x86"
	}

	return arch
}

func translateArchBtf(arch string) string {
	if arch == oci.ArchAmd64 {
		return "x86_64"
	}

	return arch
}

func newClangCompileStep(targetArch string, opts buildOptions) buildStep {
	clangCompileStep := buildStep{
		opts:       opts,
		targetArch: targetArch,
	}

	clangCompileStep.run = func(runner commandRunner) error {
		bpfObjectPath := filepath.Join(clangCompileStep.opts.outputDir, fmt.Sprintf("%s.bpf.o", clangCompileStep.targetArch))

		kernelArch, ok := goArchToKernelArch[runtime.GOARCH]
		if !ok {
			return fmt.Errorf("no kernel architecture corresponding to %q", runtime.GOARCH)
		}

		cmd := []string{
			"clang",
			"-target", "bpf",
			"-Wall",
			"-g",
			"-O2",
			fmt.Sprintf("-I/usr/include/%s-linux-gnu", kernelArch),
			"-D", fmt.Sprintf("__TARGET_ARCH_%s", translateArch(clangCompileStep.targetArch)),
			"-c", clangCompileStep.opts.ebpfSourcePath,
			"-I", fmt.Sprintf("/usr/include/gadget/%s/", clangCompileStep.targetArch),
			"-o", bpfObjectPath,
		}

		if clangCompileStep.opts.useInTreeHeaders {
			cmd = append(cmd,
				"-I", "/work/include/",
				"-I", fmt.Sprintf("/work/include/gadget/%s/", clangCompileStep.targetArch),
			)
		}

		if _, _, err := runner.run(cmd, nil); err != nil {
			return fmt.Errorf("clang compile for %s: %w", clangCompileStep.targetArch, err)
		}

		if _, _, err := runner.run([]string{"llvm-strip", "-g", bpfObjectPath}, nil); err != nil {
			return fmt.Errorf("llvm-strip for %s: %w", clangCompileStep.targetArch, err)
		}

		return nil
	}

	return clangCompileStep
}

func newGoBuildStep(opts buildOptions) buildStep {
	goBuildStep := buildStep{opts: opts}

	goBuildStep.run = func(runner commandRunner) error {
		cmd := []string{
			"go", "build",
			"-C", filepath.Dir(goBuildStep.opts.wasmSourcePath),
			"-o", filepath.Join(goBuildStep.opts.outputDir, "program.wasm"),
			// -buildmode=c-shared to build the wasm as a reactor module, see:
			// https://github.com/WebAssembly/WASI/blob/main/legacy/application-abi.md#current-unstable-abi
			"-buildmode=c-shared",
			"-ldflags", "-w -s", "--",
			filepath.Base(goBuildStep.opts.wasmSourcePath),
		}
		env := []string{
			"CGO_ENABLED=0",
			"GOOS=wasip1",
			"GOARCH=wasm",
		}

		if _, _, err := runner.run(cmd, env); err != nil {
			return fmt.Errorf("go build wasm: %w", err)
		}
		return nil
	}

	return goBuildStep
}

func newCargoBuildStep(opts buildOptions) buildStep {
	cargoBuildStep := buildStep{opts: opts}

	cargoBuildStep.run = func(runner commandRunner) error {
		cmd := []string{"cargo"}
		if cargoBuildStep.opts.forceColorsFlag {
			cmd = append(cmd, "--color", "always")
		}
		manifestPath := filepath.Join(filepath.Dir(cargoBuildStep.opts.wasmSourcePath), "..", "Cargo.toml")
		cmd = append(cmd,
			"build",
			"--target", "wasm32-wasip1", "--release",
			"--locked",
			"--manifest-path="+manifestPath,
		)
		env := []string{fmt.Sprintf("CARGO_TARGET_DIR=%s", cargoBuildStep.opts.outputDir)}

		if _, _, err := runner.run(cmd, env); err != nil {
			return fmt.Errorf("cargo build: %w", err)
		}

		metadataOut, _, err := runner.run([]string{
			"cargo", "metadata", "--format-version=1", "--no-deps",
			"--locked",
			"--manifest-path=" + manifestPath,
		}, nil)
		if err != nil {
			return fmt.Errorf("cargo metadata: %w", err)
		}

		targetName, err := cargoWasmTargetName(metadataOut)
		if err != nil {
			return err
		}

		// cargo replaces "-" by "_" in the output file name.
		src := filepath.Join(cargoBuildStep.opts.outputDir, "wasm32-wasip1", "release", strings.ReplaceAll(targetName, "-", "_")+".wasm")
		dst := filepath.Join(cargoBuildStep.opts.outputDir, "program.wasm")
		if _, _, err := runner.run([]string{"cp", "--", src, dst}, nil); err != nil {
			return fmt.Errorf("copying wasm output: %w", err)
		}

		return nil
	}

	return cargoBuildStep
}

type cargoMetadata struct {
	Packages []struct {
		Targets []struct {
			Name string   `json:"name"`
			Kind []string `json:"kind"`
		} `json:"targets"`
	} `json:"packages"`
}

var cargoTargetNameRe = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// cargoWasmTargetName returns the name of the cdylib target from the output
// of "cargo metadata --format-version=1 --no-deps".
func cargoWasmTargetName(metadataOut string) (string, error) {
	var metadata cargoMetadata
	if err := json.Unmarshal([]byte(metadataOut), &metadata); err != nil {
		return "", fmt.Errorf("parsing cargo metadata output (if using --local, try building in container): %w", err)
	}

	if len(metadata.Packages) != 1 {
		return "", fmt.Errorf("expected exactly one cargo package, got %d (cargo workspaces are not supported)", len(metadata.Packages))
	}

	var names []string
	for _, target := range metadata.Packages[0].Targets {
		if slices.Contains(target.Kind, "cdylib") {
			names = append(names, target.Name)
		}
	}

	if len(names) != 1 {
		return "", fmt.Errorf("expected exactly one cdylib target, got %d", len(names))
	}

	if !cargoTargetNameRe.MatchString(names[0]) {
		return "", fmt.Errorf("invalid cdylib target name: %q", names[0])
	}

	return names[0], nil
}

func newBtfgenStep(targetArch string, opts buildOptions) buildStep {
	btfgenStep := buildStep{
		opts:       opts,
		targetArch: targetArch,
	}

	btfgenStep.run = func(runner commandRunner) error {
		translatedArch := translateArchBtf(btfgenStep.targetArch)
		bpfObjectPath := filepath.Join(btfgenStep.opts.outputDir, fmt.Sprintf("%s.bpf.o", btfgenStep.targetArch))
		outputBtfDirPath := filepath.Join(btfgenStep.opts.outputDir, "btfs", translatedArch)
		btfArchivePath := filepath.Join(btfgenStep.opts.outputDir, fmt.Sprintf("btfs-%s.tar.gz", translatedArch))
		// Extract BTF files in the output directory rather than next to the
		// archives, so the btfhub-archive directory is only read.
		tmpBaseDir := filepath.Join(btfgenStep.opts.outputDir, "btfs-tmp")
		tmpDir := filepath.Join(tmpBaseDir, translatedArch)

		if _, _, err := runner.run([]string{"mkdir", "-p", tmpDir, outputBtfDirPath}, nil); err != nil {
			return fmt.Errorf("creating btf directories: %w", err)
		}
		defer func() {
			_, _, _ = runner.run([]string{"rm", "-rf", "--", tmpBaseDir}, nil)
		}()

		findOut, _, err := runner.run([]string{
			"find", btfgenStep.opts.btfHubArchivePath,
			"-iregex", fmt.Sprintf(".*%s.*", translatedArch),
			"-type", "f",
			"-name", "*.btf.tar.xz",
		}, nil)
		if err != nil {
			return fmt.Errorf("finding btf archives for %s: %w", translatedArch, err)
		}

		for _, btfArchiveFile := range strings.Split(strings.TrimSpace(findOut), "\n") {
			if btfArchiveFile == "" {
				continue
			}

			btfFilename := filepath.Base(strings.TrimSuffix(btfArchiveFile, ".tar.xz"))
			btfFilePath := filepath.Join(tmpDir, btfFilename)
			outputBtfFilePath := filepath.Join(outputBtfDirPath, btfFilename)

			if _, _, err := runner.run([]string{
				"tar", "xfJ", btfArchiveFile,
				"-C", tmpDir,
				"--touch",
			}, nil); err != nil {
				return fmt.Errorf("extracting %s: %w", btfArchiveFile, err)
			}

			if _, _, err := runner.run([]string{
				"bpftool", "gen", "min_core_btf", btfFilePath, outputBtfFilePath, bpfObjectPath,
			}, nil); err != nil {
				return fmt.Errorf("bpftool gen min_core_btf for %s: %w", btfFilePath, err)
			}

			if _, _, err := runner.run([]string{"rm", "-f", btfFilePath}, nil); err != nil {
				return fmt.Errorf("removing %s: %w", btfFilePath, err)
			}
		}

		if _, _, err := runner.run([]string{
			"tar", "czf", btfArchivePath, "-C", outputBtfDirPath, ".",
		}, nil); err != nil {
			return fmt.Errorf("creating btf archive for %s: %w", translatedArch, err)
		}

		return nil
	}

	return btfgenStep
}
