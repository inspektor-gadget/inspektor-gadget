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
	"debug/gosym"
	"fmt"
	"os"
)

// maxGoSectionSize is the maximum size we'll read for .gopclntab and
// .gosymtab sections. This prevents a malicious binary inside a container
// from causing excessive memory allocation in the privileged IG process.
// 64 MiB is generous: typical Go binaries have .gopclntab well under 32 MiB
// even for very large programs.
const maxGoSectionSize = 64 * 1024 * 1024

// resolveGoSymbol looks up a function address in a Go binary's .gopclntab
// section. This works even for stripped binaries where the standard ELF
// symbol table (.symtab) has been removed, because Go preserves .gopclntab
// and .gosymtab for runtime stack traces.
//
// The caller must pass an already-opened *os.File (typically obtained via
// secureopen.OpenInContainer) to avoid re-opening untrusted paths.
//
// Returns a file offset suitable for use with UprobeOptions.Address.
func resolveGoSymbol(file *os.File, symbol string) (addr uint64, err error) {
	// debug/elf and debug/gosym are not hardened against adversarial inputs
	// and may panic on malformed data. Since we're parsing files from
	// untrusted containers, recover from panics.
	defer func() {
		if r := recover(); r != nil {
			addr = 0
			err = fmt.Errorf("panic parsing Go symbol table: %v", r)
		}
	}()

	f, err := elf.NewFile(file)
	if err != nil {
		return 0, fmt.Errorf("reading ELF: %w", err)
	}
	defer f.Close()

	pclntab := f.Section(".gopclntab")
	if pclntab == nil {
		return 0, fmt.Errorf("no .gopclntab section found (not a Go binary?)")
	}
	if pclntab.Size > maxGoSectionSize {
		return 0, fmt.Errorf(".gopclntab too large (%d bytes, max %d)", pclntab.Size, maxGoSectionSize)
	}

	// .gosymtab may be absent in stripped binaries. Go 1.16+ embeds all
	// needed information in .gopclntab, so gosym.NewTable works with nil symtab.
	var symtabData []byte
	if symtab := f.Section(".gosymtab"); symtab != nil {
		if symtab.Size > maxGoSectionSize {
			return 0, fmt.Errorf(".gosymtab too large (%d bytes, max %d)", symtab.Size, maxGoSectionSize)
		}
		symtabData, err = symtab.Data()
		if err != nil {
			return 0, fmt.Errorf("reading .gosymtab: %w", err)
		}
	}

	textSection := f.Section(".text")
	if textSection == nil {
		return 0, fmt.Errorf("no .text section found")
	}

	pclntabData, err := pclntab.Data()
	if err != nil {
		return 0, fmt.Errorf("reading .gopclntab: %w", err)
	}

	lineTable := gosym.NewLineTable(pclntabData, textSection.Addr)
	table, err := gosym.NewTable(symtabData, lineTable)
	if err != nil {
		return 0, fmt.Errorf("parsing Go symbol table: %w", err)
	}

	fn := table.LookupFunc(symbol)
	if fn == nil {
		return 0, fmt.Errorf("symbol %q not found in .gopclntab", symbol)
	}

	// Convert virtual address to file offset using the executable LOAD segment.
	// The uprobe subsystem needs a file offset, not a virtual address.
	for _, prog := range f.Progs {
		if prog.Type != elf.PT_LOAD || (prog.Flags&elf.PF_X) == 0 {
			continue
		}
		if prog.Vaddr <= fn.Entry && fn.Entry < (prog.Vaddr+prog.Memsz) {
			return fn.Entry - prog.Vaddr + prog.Off, nil
		}
	}

	return 0, fmt.Errorf("symbol %q (VA 0x%x) not found in any executable LOAD segment", symbol, fn.Entry)
}
