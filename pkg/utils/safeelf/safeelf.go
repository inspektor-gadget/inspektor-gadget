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

// Package safeelf provides panic-safe, hardened wrappers around debug/elf.
//
// Go's debug/elf is not hardened against adversarial inputs and may panic on
// malformed data or allocate excessive memory for crafted sections. Since
// Inspektor Gadget parses ELF files from untrusted containers in a privileged
// process, this package:
//   - Wraps all operations in recover() to turn panics into errors
//   - Replaces the unbounded symbol accessors with a bounded iterator
package safeelf

import (
	"bufio"
	"bytes"
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

const (
	// maxStrtabSectionSize is the maximum size of a .strtab/.dynstr section.
	// Measured on large real-world binaries, .strtab stays well below this:
	// dockerd 8.8 MiB, ig 8.6 MiB, docker 2.8 MiB, runc 0.6 MiB. The same
	// 16 MiB bound is used by opentelemetry-ebpf-profiler for ELF string
	// tables (libpf/pfelf.maxBytesLargeSection).
	maxStrtabSectionSize = 16 * 1024 * 1024

	// maxSymbolNameSize is the maximum size of a single symbol name.
	maxSymbolNameSize = 64 * 1024

	// symtabReadBufferSize is the buffer used to stream symbol table entries.
	symtabReadBufferSize = 64 * 1024

	// maxSymbolCount is the maximum number of symbols iterated.
	maxSymbolCount = 10 * 1000 * 1000

	// maxSymtabSectionSize is the maximum size of a .symtab/.dynsym section.
	// It matches maxSymbolCount entries of the largest symbol entry size.
	maxSymtabSectionSize = maxSymbolCount * int(elf.Sym64Size)
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

// ErrUnboundedSymbols is returned by Symbols and DynamicSymbols. Callers must
// use IterateSymbols instead.
var ErrUnboundedSymbols = errors.New("safeelf: unbounded symbol table read, use IterateSymbols instead")

// Symbols shadows the promoted elf.File.Symbols and always fails.
//
// debug/elf returns the whole table as a []elf.Symbol, which costs ~187 bytes
// per symbol once names and slice growth are counted. Bounding the section
// sizes does not bound that slice, so a crafted binary can still force a
// multi-gigabyte allocation in a privileged process. This method only exists
// to shadow the embedded *elf.File, which would otherwise be promoted and
// silently reachable.
func (f *File) Symbols() ([]elf.Symbol, error) {
	return nil, ErrUnboundedSymbols
}

// DynamicSymbols shadows the promoted elf.File.DynamicSymbols and always fails.
// See Symbols.
func (f *File) DynamicSymbols() ([]elf.Symbol, error) {
	return nil, ErrUnboundedSymbols
}

// symbolEntry is the internal parsed ELF symbol entry used during iteration.
type symbolEntry struct {
	info    uint8
	other   uint8
	shndx   uint16
	value   uint64
	size    uint64
	nameOff uint32
}

// symbolIterator iterates over ELF symbol table entries without loading the
// symbol table or string table into memory.
type symbolIterator struct {
	symtab    *bufio.Reader
	strtab    []byte
	order     func([]byte) uint64
	order32   func([]byte) uint32
	order16   func([]byte) uint16
	entrySize int
	class     elf.Class
	count     int
}

// next returns the next symbol entry. Returns io.EOF when done.
func (it *symbolIterator) next() (symbolEntry, error) {
	if it.count >= maxSymbolCount {
		return symbolEntry{}, fmt.Errorf("symbol count exceeds limit (%d)", maxSymbolCount)
	}

	var buf [24]byte // max(Sym64Size, Sym32Size)
	d := buf[:it.entrySize]
	if _, err := io.ReadFull(it.symtab, d); err != nil {
		if errors.Is(err, io.EOF) {
			return symbolEntry{}, io.EOF
		}
		return symbolEntry{}, fmt.Errorf("reading symbol entry: %w", err)
	}

	var entry symbolEntry
	switch it.class {
	case elf.ELFCLASS64:
		entry.nameOff = it.order32(d[0:4])
		entry.info = d[4]
		entry.other = d[5]
		entry.shndx = it.order16(d[6:8])
		entry.value = it.order(d[8:16])
		entry.size = it.order(d[16:24])
	case elf.ELFCLASS32:
		entry.nameOff = it.order32(d[0:4])
		entry.value = uint64(it.order32(d[4:8]))
		entry.size = uint64(it.order32(d[8:12]))
		entry.info = d[12]
		entry.other = d[13]
		entry.shndx = it.order16(d[14:16])
	}

	it.count++
	return entry, nil
}

// symbolName returns the name of the given symbol entry from the string
// table. The string table is bounded by maxStrtabSectionSize and read once
// when the iterator is created, so this is a pure in-memory lookup.
func (it *symbolIterator) symbolName(entry symbolEntry) (string, error) {
	off := uint64(entry.nameOff)
	if off >= uint64(len(it.strtab)) {
		return "", fmt.Errorf("symbol name offset %d out of string table bounds (size %d)",
			off, len(it.strtab))
	}

	if off == 0 {
		return "", nil
	}

	name := it.strtab[off:]
	if len(name) > maxSymbolNameSize {
		name = name[:maxSymbolNameSize]
	}

	i := bytes.IndexByte(name, 0)
	if i < 0 {
		return "", fmt.Errorf("symbol name at offset %d is unterminated within %d bytes",
			off, len(name))
	}

	return string(name[:i]), nil
}

// newSymbolIterator creates an iterator for the given symbol table type.
// Returns nil with no error if the section does not exist.
func (f *File) newSymbolIterator(typ elf.SectionType) (_ *symbolIterator, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("panic creating symbol iterator: %v", r)
		}
	}()

	symtabSection := f.File.SectionByType(typ)
	if symtabSection == nil {
		return nil, nil
	}

	if symtabSection.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("compressed symbol table section not supported")
	}

	var entrySize int
	switch f.File.Class {
	case elf.ELFCLASS64:
		entrySize = int(elf.Sym64Size) // 24
	case elf.ELFCLASS32:
		entrySize = int(elf.Sym32Size) // 16
	default:
		return nil, fmt.Errorf("unsupported ELF class: %v", f.File.Class)
	}

	if symtabSection.Size > uint64(maxSymtabSectionSize) {
		return nil, fmt.Errorf("symbol table section too large: %d bytes (max %d)",
			symtabSection.Size, maxSymtabSectionSize)
	}

	if symtabSection.Size%uint64(entrySize) != 0 {
		return nil, fmt.Errorf("symbol table size %d is not a multiple of entry size %d",
			symtabSection.Size, entrySize)
	}

	if symtabSection.ReaderAt == nil {
		return nil, fmt.Errorf("symbol table section has no ReaderAt")
	}

	// Validate the linked string table section.
	link := symtabSection.Link
	if int(link) >= len(f.File.Sections) {
		return nil, fmt.Errorf("symbol table link %d out of range (have %d sections)",
			link, len(f.File.Sections))
	}

	strtabSection := f.File.Sections[link]
	if strtabSection.Type != elf.SHT_STRTAB {
		return nil, fmt.Errorf("linked section %d has type %v, expected SHT_STRTAB",
			link, strtabSection.Type)
	}

	if strtabSection.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("compressed string table section not supported")
	}

	if strtabSection.Size > maxStrtabSectionSize {
		return nil, fmt.Errorf("string table section too large: %d bytes (max %d)",
			strtabSection.Size, maxStrtabSectionSize)
	}

	if strtabSection.ReaderAt == nil {
		return nil, fmt.Errorf("string table section has no ReaderAt")
	}

	// Read the string table once. Its size is bounded above, and resolving
	// names with one read per symbol instead would let a crafted binary with
	// many symbols burn CPU in the privileged process.
	strtab := make([]byte, strtabSection.Size)
	if _, err := io.ReadFull(io.NewSectionReader(strtabSection.ReaderAt, 0,
		int64(strtabSection.Size)), strtab); err != nil {
		return nil, fmt.Errorf("reading string table: %w", err)
	}

	bo := f.File.ByteOrder

	// Skip the first entry, which is all zeros per the ELF spec.
	symtabReader := io.NewSectionReader(symtabSection.ReaderAt,
		int64(entrySize), int64(symtabSection.Size)-int64(entrySize))

	return &symbolIterator{
		symtab:  bufio.NewReaderSize(symtabReader, symtabReadBufferSize),
		strtab:  strtab,
		order32: bo.Uint32,
		order16: bo.Uint16,
		order: func(b []byte) uint64 {
			return bo.Uint64(b)
		},
		entrySize: entrySize,
		class:     f.File.Class,
	}, nil
}

// IterateSymbols calls fn for each symbol in the given section type (SHT_SYMTAB
// or SHT_DYNSYM). Returns nil if the section doesn't exist. fn returns true to
// stop iteration early. Symbol table entries are streamed, and every section
// read is bounded, so memory use does not depend on the number of symbols.
//
// Unlike elf.File.DynamicSymbols, the version fields (HasVersion, VersionIndex,
// Version and Library) are not populated for SHT_DYNSYM: doing so requires
// parsing .gnu.version and .gnu.version_r, which no caller needs. All other
// fields match debug/elf exactly.
func (f *File) IterateSymbols(typ elf.SectionType, fn func(sym elf.Symbol) bool) error {
	iter, err := f.newSymbolIterator(typ)
	if err != nil {
		return err
	}
	if iter == nil {
		return nil
	}

	for {
		entry, err := iter.next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("iterating symbols: %w", err)
		}

		name, err := iter.symbolName(entry)
		if err != nil {
			return fmt.Errorf("reading symbol name: %w", err)
		}

		sym := elf.Symbol{
			Name:    name,
			Info:    entry.info,
			Other:   entry.other,
			Section: elf.SectionIndex(entry.shndx),
			Value:   entry.value,
			Size:    entry.size,
		}

		if fn(sym) {
			return nil
		}
	}
}
