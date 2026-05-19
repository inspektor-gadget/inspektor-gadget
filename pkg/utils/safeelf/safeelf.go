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

// Package safeelf provides panic-safe wrappers around debug/elf.
//
// Go's debug/elf is not hardened against adversarial inputs and may panic on
// malformed data. Since Inspektor Gadget parses ELF files from untrusted
// containers in a privileged process, we wrap all operations in recover() to
// turn panics into errors.
//
// This approach is inspired by cilium/ebpf's internal SafeELFFile:
// https://github.com/cilium/ebpf/blob/main/internal/elf.go
package safeelf

import (
	"debug/elf"
	"fmt"
	"io"
)

// File wraps an *elf.File with panic recovery on operations that may crash
// on malformed input.
type File struct {
	*elf.File
}

// NewFile reads an ELF file safely. Any panic during parsing is turned into
// an error.
func NewFile(r io.ReaderAt) (safe *File, err error) {
	defer func() {
		if r := recover(); r != nil {
			safe = nil
			err = fmt.Errorf("panic reading ELF file: %v", r)
		}
	}()

	f, err := elf.NewFile(r)
	if err != nil {
		return nil, err
	}

	return &File{f}, nil
}

// Symbols is the safe version of elf.File.Symbols.
func (f *File) Symbols() (syms []elf.Symbol, err error) {
	defer func() {
		if r := recover(); r != nil {
			syms = nil
			err = fmt.Errorf("panic reading ELF symbols: %v", r)
		}
	}()

	return f.File.Symbols()
}

// DynamicSymbols is the safe version of elf.File.DynamicSymbols.
func (f *File) DynamicSymbols() (syms []elf.Symbol, err error) {
	defer func() {
		if r := recover(); r != nil {
			syms = nil
			err = fmt.Errorf("panic reading ELF dynamic symbols: %v", r)
		}
	}()

	return f.File.DynamicSymbols()
}
