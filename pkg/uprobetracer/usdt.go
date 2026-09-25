// Copyright 2024 The Inspektor Gadget authors
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
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/safeelf"
)

// For details regarding the data format of USDT notes, please refer to:
// https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
const (
	sdtNoteSectionName = ".note.stapsdt"
	sdtBaseSectionName = ".stapsdt.base"

	// maxNoteFieldSize limits the size of individual note name/desc fields to
	// prevent excessive memory allocation from malformed ELF files. There is no
	// standard upper bound for ELF note fields; 1 MiB is a generous arbitrary
	// cap — legitimate USDT notes are typically under 1 KB.
	maxNoteFieldSize = 1024 * 1024

	// maxNoteCount limits the number of notes iterated to prevent CPU denial
	// of service from a crafted section with millions of tiny valid notes.
	// 10,000 is far more than any legitimate binary would have.
	maxNoteCount = 10000

	// maxNoteSectionSize limits the total number of bytes consumed from the
	// note section. maxNoteFieldSize and maxNoteCount only bound each note
	// individually, so on their own they still allow 10,000 * 1 MiB of notes.
	// 16 MiB is far beyond any legitimate .note.stapsdt section, which is
	// typically a few KiB.
	maxNoteSectionSize = 16 * 1024 * 1024
)

type noteHeader struct {
	NameSize uint32
	DescSize uint32
	Type     uint32
}

type usdtAttachInfo struct {
	attachAddress    uint64
	semaphoreAddress uint64
}

// vaddr2ElfOffset maps a virtual address to an offset in the ELF file.
//
// The program headers come from an untrusted file, so every field is
// validated before use and the arithmetic is overflow-safe.
func vaddr2ElfOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		// Only PT_LOAD segments describe the memory image. Other segment
		// types overlap them, so a crafted one could otherwise be used to
		// redirect the mapping to an arbitrary file offset.
		if prog.Type != elf.PT_LOAD {
			continue
		}
		if addr < prog.Vaddr {
			continue
		}

		// Compare the offset within the segment rather than
		// prog.Vaddr+prog.Filesz: on ELFCLASS64 both come straight from the
		// file and their sum can wrap. On ELFCLASS32 they are widened from
		// 32-bit fields and cannot.
		//
		// Filesz, not Memsz: the tail of a segment that is only memory
		// resident, such as .bss, has no corresponding bytes in the file, so
		// an address there has no file offset to attach to.
		offsetInProg := addr - prog.Vaddr
		if offsetInProg >= prog.Filesz {
			continue
		}

		fileOffset := prog.Off + offsetInProg
		if fileOffset < prog.Off {
			continue
		}
		return fileOffset, nil
	}
	return 0, fmt.Errorf("malformed elf file: elf prog containing addr %x not found", addr)
}

func alignUp[T int | int32 | int64 | uint | uint32 | uint64](n T, align T) T {
	return (n + align - 1) / align * align
}

// getUsdtInfo parses the USDT notes of an ELF file that may come from an
// untrusted container. Any panic escaping the parser is turned into an error
// so that malformed input cannot terminate the privileged process: the parser
// runs on a container-attach goroutine that has no panic recovery of its own.
func getUsdtInfo(filepath string, attachSymbol string) (info *usdtAttachInfo, err error) {
	defer func() {
		if r := recover(); r != nil {
			info = nil
			err = fmt.Errorf("panic parsing USDT notes of %q: %v", filepath, r)
		}
	}()

	return parseUsdtNotes(filepath, attachSymbol)
}

func parseUsdtNotes(filepath string, attachSymbol string) (*usdtAttachInfo, error) {
	parts := strings.Split(attachSymbol, ":")
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid USDT section name: %q", attachSymbol)
	}
	providerName := parts[0]
	probeName := parts[1]

	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %w", filepath, err)
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stating file %q: %w", filepath, err)
	}
	if !fileInfo.Mode().IsRegular() {
		return nil, fmt.Errorf("ELF file %q is not regular", filepath)
	}

	elfReader, err := safeelf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading elf file %q: %w", filepath, err)
	}
	defer elfReader.Close()

	noteSection := elfReader.Section(sdtNoteSectionName)
	if noteSection == nil {
		return nil, errors.New("USDT note section does not exist")
	}
	if noteSection.Type != elf.SHT_NOTE {
		return nil, fmt.Errorf("section %q is not a note", sdtNoteSectionName)
	}
	// Reject compressed note sections, as pkg/utils/safeelf does for symbol
	// and string tables. Section.Open() would transparently decompress them,
	// letting a small file expand to an arbitrary amount of data. No toolchain
	// compresses this section: it holds a few KiB of probe descriptors.
	if noteSection.Flags&elf.SHF_COMPRESSED != 0 {
		return nil, fmt.Errorf("compressed %q section not supported", sdtNoteSectionName)
	}
	// Bound the bytes actually read. The size declared in the section header
	// is attacker-controlled and cannot be used for this: debug/elf does not
	// enforce it when reading through Open(), it only uses it to seek.
	notesReader := io.LimitReader(noteSection.Open(), maxNoteSectionSize)

	baseSection := elfReader.Section(sdtBaseSectionName)
	if baseSection == nil {
		return nil, errors.New("USDT base section does not exist")
	}
	if baseSection.Type != elf.SHT_PROGBITS {
		return nil, fmt.Errorf("%q is not a program defined section", sdtBaseSectionName)
	}

	wordSize := 4
	if elfReader.Class == elf.ELFCLASS64 {
		wordSize = 8
	}

	// Address fields are wordSize bytes wide, so they must be read at that
	// width. Reading them with Uint64 on an ELFCLASS32 file would read past
	// the end of the desc slice and panic.
	readAddr := func(b []byte) uint64 {
		if wordSize == 8 {
			return elfReader.ByteOrder.Uint64(b)
		}
		return uint64(elfReader.ByteOrder.Uint32(b))
	}

	// Minimum desc size for a stapsdt note: 3 address fields.
	minDescSize := 3 * wordSize

	// walk through USDT notes, and match with providerName and probeName
	// For details of the structure of ELF notes, please refer to
	// https://man7.org/linux/man-pages/man5/elf.5.html, the `Notes (Nhdr)` section
	noteCount := 0
	for {
		var header noteHeader
		err = binary.Read(notesReader, elfReader.ByteOrder, &header)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("reading USDT note header: %w", err)
		}

		noteCount++
		if noteCount > maxNoteCount {
			return nil, fmt.Errorf("too many USDT notes (%d, max %d)", noteCount, maxNoteCount)
		}

		alignedNameSize := alignUp(uint64(header.NameSize), 4)
		alignedDescSize := alignUp(uint64(header.DescSize), 4)

		if alignedNameSize > maxNoteFieldSize {
			return nil, fmt.Errorf("USDT note name too large: %d bytes", alignedNameSize)
		}
		if alignedDescSize > maxNoteFieldSize {
			return nil, fmt.Errorf("USDT note desc too large: %d bytes", alignedDescSize)
		}

		name := make([]byte, alignedNameSize)
		err = binary.Read(notesReader, elfReader.ByteOrder, &name)
		if err != nil {
			return nil, fmt.Errorf("reading USDT note name: %w", err)
		}

		desc := make([]byte, alignedDescSize)
		err = binary.Read(notesReader, elfReader.ByteOrder, &desc)
		if err != nil {
			return nil, fmt.Errorf("reading USDT note desc: %w", err)
		}

		if string(name) != "stapsdt\x00" || header.Type != 3 {
			continue
		}

		if len(desc) < minDescSize {
			return nil, fmt.Errorf("malformed stapsdt note: desc too short (%d bytes, need %d)", len(desc), minDescSize)
		}

		elfLocation := readAddr(desc[:wordSize])
		elfBase := readAddr(desc[wordSize : 2*wordSize])
		elfSemaphore := readAddr(desc[2*wordSize : 3*wordSize])

		diff := baseSection.Addr - elfBase
		location, err := vaddr2ElfOffset(elfReader.File, elfLocation+diff)
		if err != nil {
			return nil, err
		}

		if elfSemaphore != 0 {
			elfSemaphore, err = vaddr2ElfOffset(elfReader.File, elfSemaphore+diff)
			if err != nil {
				return nil, err
			}
		}

		provider := readStringFromBytes(desc, uint32(3*wordSize))
		probe := readStringFromBytes(desc, uint32(3*wordSize+len(provider)+1))
		if provider == providerName && probe == probeName {
			return &usdtAttachInfo{location, elfSemaphore}, nil
		}
	}
	return nil, errors.New("no matching USDT metadata")
}
