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
	"fmt"
	"path/filepath"
	"runtime"
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
			"-ldflags", "-w -s",
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
		cmd = append(cmd,
			"build",
			"--target", "wasm32-wasip1", "--release",
			"--manifest-path", filepath.Join(filepath.Dir(cargoBuildStep.opts.wasmSourcePath), "..", "Cargo.toml"),
		)
		env := []string{fmt.Sprintf("CARGO_TARGET_DIR=%s", cargoBuildStep.opts.outputDir)}

		if _, _, err := runner.run(cmd, env); err != nil {
			return fmt.Errorf("cargo build: %w", err)
		}

		cargoTomlPath := filepath.Join(filepath.Dir(cargoBuildStep.opts.wasmSourcePath), "..", "Cargo.toml")
		awkOut, _, err := runner.run([]string{
			"awk", "-F", `"`, `/^name *=/ { print $2; exit }`, cargoTomlPath,
		}, nil)
		if err != nil {
			return fmt.Errorf("reading package name from Cargo.toml: %w", err)
		}
		packageName := strings.TrimSpace(awkOut)

		src := filepath.Join(cargoBuildStep.opts.outputDir, "wasm32-wasip1", "release", packageName+".wasm")
		dst := filepath.Join(cargoBuildStep.opts.outputDir, "program.wasm")
		if _, _, err := runner.run([]string{"cp", src, dst}, nil); err != nil {
			return fmt.Errorf("copying wasm output: %w", err)
		}

		return nil
	}

	return cargoBuildStep
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

			btfFilePath := strings.TrimSuffix(btfArchiveFile, ".tar.xz")
			btfFilename := filepath.Base(btfFilePath)
			outputBtfFilePath := filepath.Join(outputBtfDirPath, btfFilename)

			if _, _, err := runner.run([]string{
				"tar", "xfJ", btfArchiveFile,
				"-C", filepath.Dir(btfArchiveFile),
				"--touch",
			}, nil); err != nil {
				return fmt.Errorf("extracting %s: %w", btfArchiveFile, err)
			}

			if _, _, err := runner.run([]string{"mkdir", "-p", outputBtfDirPath}, nil); err != nil {
				return fmt.Errorf("creating btf output dir: %w", err)
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
