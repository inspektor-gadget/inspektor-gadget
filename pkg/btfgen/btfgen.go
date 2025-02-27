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

// Package btfgen provides a way to load BTF information generated with btfgen. Files to be
// included into the binary have to be generated with BTFGen (make btfgen on the root) before
// compiling the binary.
package btfgen

import (
	"bufio"
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// GetBTFSpec returns the BTF spec with kernel information for the current kernel version. If the
// kernel exposes BTF information, it returns it. If the BTF for this kernel is not found, it returns nil.
func GetBTFSpec(programs ...*ebpf.ProgramSpec) *btf.Spec {
	// If the kernel exposes BTF; nothing to do
	var opts *btf.SpecOptions
	if len(programs) > 0 {
		opts = &btf.SpecOptions{
			TypeNames: map[string]struct{}{},
		}
		for _, p := range programs {
			iter := p.Instructions.Iterate()
			for iter.Next() {
				if relo := btf.CORERelocationMetadata(iter.Ins); relo != nil {
					//fmt.Printf("relo %s\n", relo.String())
					opts.TypeNames[relo.TypeName()] = struct{}{}
				}
			}
		}
	}
	//opts = nil
	s, err := btf.LoadKernelSpecWithOptions(opts)
	if err == nil {
		return s
	}
	if err != nil {
		log.Warnf("DEBUG: Failed to initialize BTF: %v", err)
		panic("TODO: remove this panic to support kernels without BTF thanks to btfgen")
	}

	info, err := GetOSInfo()
	if err != nil {
		log.Warnf("Failed to initialize BTF: %v", err)
		return nil
	}

	// architecture naming is a mess:
	// - Golang uses amd64 and arm64
	// - btfhub uses x86_64 and arm64
	// - bpf2go uses x86 and arm64
	goarch := runtime.GOARCH
	if goarch == "amd64" {
		goarch = "x86"
	}

	btfFile := fmt.Sprintf("btfs/%s/%s/%s/%s/%s.btf",
		goarch, info.ID, info.VersionID, info.Arch, info.Kernel)

	file, err := btfs.ReadFile(btfFile)
	if err != nil {
		log.Warnf("Failed to initialize BTF: reading %s BTF file %w", btfFile, err)
		return nil
	}

	s, err = btf.LoadSpecFromReaderWithOptions(bytes.NewReader(file), opts)
	if err != nil {
		log.Warnf("Failed to initialize BTF: loading BTF spec: %w", err)
		return nil
	}

	return s
}

type OsInfo struct {
	ID        string
	VersionID string
	Arch      string
	Kernel    string
}

func GetOSInfo() (*OsInfo, error) {
	osInfo := &OsInfo{}

	file, err := os.Open(filepath.Join(host.HostRoot, "/etc/os-release"))
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		switch parts[0] {
		case "ID":
			osInfo.ID = parts[1]
		case "VERSION_ID":
			osInfo.VersionID = strings.Trim(parts[1], "\"")
		}
	}

	if osInfo.ID == "" || osInfo.VersionID == "" {
		return nil, fmt.Errorf("os-release file is incomplete")
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning file: %w", err)
	}

	uts := &unix.Utsname{}
	if err := unix.Uname(uts); err != nil {
		return nil, fmt.Errorf("calling uname: %w", err)
	}

	osInfo.Kernel = unix.ByteSliceToString(uts.Release[:])
	osInfo.Arch = unix.ByteSliceToString(uts.Machine[:])

	return osInfo, nil
}
