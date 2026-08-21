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

package uprobetracer

import (
	"debug/elf"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// The linker-built fixture matrix is:
//
// | Build variant             | Non-PIE | PIE | Stripped (-s -w)  |
// |---------------------------|---------|-----|-------------------|
// | Pure Go                   | Yes     | Yes | Yes               |
// | cgo/dynamic               | Yes     | Yes | No                |
//
// Non-stripped fixtures are cross-checked with go tool nm. External strip
// variants are tested separately:
//
// | Fixture       | --strip-all/unneeded | --strip-debug |
// |---------------|----------------------|---------------|
// | Pure Go       | Resolves             | Resolves      |
// | cgo/dynamic   | Resolves             | Resolves      |
//
// Statically linked cgo, actual kubelet/containerd binaries, and sectionless
// pclntab data are not tested.
const (
	goSymbolFixture  = "testdata/gosymbol/main.go"
	cgoSymbolFixture = "testdata/gosymbol/main_cgo.go"
)

func TestResolveGoSymbolFixtures(t *testing.T) {
	tests := []struct {
		name     string
		flags    []string
		stripped bool
	}{
		{name: "static", flags: nil},
		{name: "pie", flags: []string{"-buildmode=pie"}},
		{name: "stripped", flags: nil, stripped: true},
		{name: "pie-stripped", flags: []string{"-buildmode=pie"}, stripped: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testGoSymbolFixture(t, goSymbolFixture, nil, tt.flags, tt.stripped)
		})
	}
}

func TestResolveGoSymbolCgoFixtures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("cgo ELF fixture requires Linux")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("cgo compiler unavailable: %v", err)
	}

	for _, tt := range []struct {
		name  string
		flags []string
	}{
		{name: "non-pie", flags: nil},
		{name: "pie", flags: []string{"-buildmode=pie"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testGoSymbolFixture(t, cgoSymbolFixture, []string{"CGO_ENABLED=1"}, tt.flags, false)
		})
	}
}

func TestResolveGoSymbolExternalStripFixtures(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("external strip ELF fixture requires Linux")
	}
	strip, err := exec.LookPath("strip")
	if err != nil {
		t.Skipf("strip unavailable: %v", err)
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("cgo compiler unavailable: %v", err)
	}

	for _, fixture := range []struct {
		name   string
		source string
		env    []string
	}{
		{name: "go", source: goSymbolFixture},
		{name: "cgo", source: cgoSymbolFixture, env: []string{"CGO_ENABLED=1"}},
	} {
		for _, build := range []struct {
			name  string
			flags []string
		}{
			{name: "non-pie"},
			{name: "pie", flags: []string{"-buildmode=pie"}},
		} {
			for _, mode := range []string{"--strip-all", "--strip-unneeded", "--strip-debug"} {
				t.Run(fixture.name+"/"+build.name+"/"+strings.TrimPrefix(mode, "--"), func(t *testing.T) {
					dir := t.TempDir()
					target := filepath.Join(dir, "target")
					buildGoFixture(t, fixture.source, target, fixture.env, build.flags)

					output, err := exec.Command(strip, mode, target).CombinedOutput()
					require.NoError(t, err, "strip failed: %s", output)

					file, err := os.Open(target)
					require.NoError(t, err)
					t.Cleanup(func() { _ = file.Close() })

					got, err := resolveGoSymbol(file, "main.target")
					require.NoError(t, err)

					output, err = exec.Command(target).CombinedOutput()
					require.NoError(t, err, "fixture failed: %s", output)
					want, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
					require.NoError(t, err, "invalid fixture output: %q", output)
					require.Equal(t, want, got)
				})
			}
		}
	}
}

func testGoSymbolFixture(t *testing.T, source string, env, flags []string, stripped bool) {
	t.Helper()

	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	targetFlags := append([]string{}, flags...)
	if stripped {
		targetFlags = append(targetFlags, "-ldflags=-s -w")
	}
	buildGoFixture(t, source, target, env, targetFlags)

	file, err := os.Open(target)
	require.NoError(t, err)
	t.Cleanup(func() { _ = file.Close() })

	got, err := resolveGoSymbol(file, "main.target")
	require.NoError(t, err)

	output, err := exec.Command(target).CombinedOutput()
	require.NoError(t, err, "fixture failed: %s", output)
	want, err := strconv.ParseUint(strings.TrimSpace(string(output)), 10, 64)
	require.NoError(t, err, "invalid fixture output: %q", output)
	if !stripped {
		nmWant, err := goToolNMSymbolOffset(target, "main.target")
		require.NoError(t, err)
		require.Equal(t, nmWant, want)
	}
	require.Equal(t, want, got)
}

func buildGoFixture(t *testing.T, source, output string, env, flags []string) {
	t.Helper()

	args := []string{"build", "-o", output}
	args = append(args, flags...)
	args = append(args, source, filepath.Join(filepath.Dir(source), "runtime_offset.go"))
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), env...)
	outputBytes, err := cmd.CombinedOutput()
	require.NoError(t, err, "go build failed: %s", outputBytes)
}

func goToolNMSymbolOffset(path, name string) (uint64, error) {
	output, err := exec.Command("go", "tool", "nm", path).CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("running go tool nm: %w: %s", err, output)
	}

	var virtualAddress uint64
	for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[2] == name {
			virtualAddress, err = strconv.ParseUint(fields[0], 16, 64)
			if err != nil {
				return 0, fmt.Errorf("parsing symbol address: %w", err)
			}
			break
		}
	}
	if virtualAddress == 0 {
		return 0, fmt.Errorf("symbol %q not found", name)
	}

	elfFile, err := elf.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening ELF: %w", err)
	}
	defer elfFile.Close()

	for _, prog := range elfFile.Progs {
		if prog.Type != elf.PT_LOAD || prog.Flags&elf.PF_X == 0 {
			continue
		}
		if virtualAddress < prog.Vaddr || virtualAddress-prog.Vaddr >= prog.Memsz {
			continue
		}
		return prog.Off + virtualAddress - prog.Vaddr, nil
	}
	return 0, fmt.Errorf("symbol %q is not in an executable LOAD segment", name)
}

// makePclntabHeader builds a minimal pclntab header with the given magic,
// pointer size and function count.
func makePclntabHeader(magic uint32, ptrSize byte, funcCount uint64) []byte {
	data := make([]byte, 64)
	binary.LittleEndian.PutUint32(data[0:4], magic)
	data[7] = ptrSize
	if ptrSize == 4 {
		binary.LittleEndian.PutUint32(data[8:], uint32(funcCount))
	} else {
		binary.LittleEndian.PutUint64(data[8:], funcCount)
	}
	return data
}

func TestPclntabFuncCount(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		expected  uint64
		expectErr string
	}{
		{
			name:     "go118_64bit",
			data:     makePclntabHeader(0xfffffff0, 8, 103189),
			expected: 103189,
		},
		{
			name:     "go12_32bit",
			data:     makePclntabHeader(0xfffffffb, 4, 4242),
			expected: 4242,
		},
		{
			name:      "too_short",
			data:      makePclntabHeader(0xfffffff0, 8, 1)[:31],
			expectErr: "too short",
		},
		{
			name:      "bad_magic",
			data:      makePclntabHeader(0xdeadbeef, 8, 1),
			expectErr: "invalid Go pclntab magic",
		},
		{
			name:      "bad_pointer_size",
			data:      makePclntabHeader(0xfffffff0, 3, 1),
			expectErr: "unsupported Go pclntab pointer size",
		},
		{
			// A crafted section can declare far more functions than
			// it has room for, which debug/gosym would allocate.
			name:     "implausible_count",
			data:     makePclntabHeader(0xfffffff0, 8, ^uint64(0)),
			expected: ^uint64(0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			count, err := pclntabFuncCount(tt.data, binary.LittleEndian)
			if tt.expectErr != "" {
				require.ErrorContains(t, err, tt.expectErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.expected, count)
			if tt.name == "implausible_count" {
				require.Greater(t, count, uint64(maxGoFuncCount),
					"resolveGoSymbol must reject this count")
			}
		})
	}
}
