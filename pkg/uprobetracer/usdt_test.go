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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	testStapsdtBaseAddr = 0x1000
	testLoadSegmentSize = 0x10000
)

// buildUsdtELF builds a minimal little-endian ELF containing a single
// PT_LOAD segment mapped at vaddr 0, a ".note.stapsdt" section holding one
// stapsdt note with the given desc, and a ".stapsdt.base" section at
// testStapsdtBaseAddr. It is used to exercise the USDT note parser with
// inputs that a real toolchain would not produce.
func buildUsdtELF(class elf.Class, desc []byte) []byte {
	le := binary.LittleEndian
	is64 := class == elf.ELFCLASS64

	note := make([]byte, 12)
	le.PutUint32(note[0:], 8)                 // NameSize, len("stapsdt\x00")
	le.PutUint32(note[4:], uint32(len(desc))) // DescSize
	le.PutUint32(note[8:], 3)                 // Type, NT_STAPSDT
	note = append(note, []byte("stapsdt\x00")...)
	note = append(note, desc...)

	shstr := []byte{0}
	nameOff := func(s string) uint32 {
		off := uint32(len(shstr))
		shstr = append(shstr, []byte(s)...)
		shstr = append(shstr, 0)
		return off
	}
	offNote := nameOff(sdtNoteSectionName)
	offBase := nameOff(sdtBaseSectionName)
	offShstr := nameOff(".shstrtab")

	var ehSize, phEntSize, shEntSize uint32
	if is64 {
		ehSize, phEntSize, shEntSize = 64, 56, 64
	} else {
		ehSize, phEntSize, shEntSize = 52, 32, 40
	}
	phOff := ehSize
	noteOff := phOff + phEntSize
	baseOff := noteOff + uint32(len(note))
	shstrOff := baseOff
	shOff := shstrOff + uint32(len(shstr))

	buf := make([]byte, shOff+4*shEntSize)
	copy(buf, []byte{0x7f, 'E', 'L', 'F'})
	buf[4] = byte(class)
	buf[5] = byte(elf.ELFDATA2LSB)
	buf[6] = byte(elf.EV_CURRENT)

	le.PutUint16(buf[16:], uint16(elf.ET_EXEC))
	le.PutUint32(buf[20:], uint32(elf.EV_CURRENT))
	if is64 {
		le.PutUint16(buf[18:], uint16(elf.EM_X86_64))
		le.PutUint64(buf[32:], uint64(phOff))
		le.PutUint64(buf[40:], uint64(shOff))
		le.PutUint16(buf[52:], uint16(ehSize))
		le.PutUint16(buf[54:], uint16(phEntSize))
		le.PutUint16(buf[56:], 1)
		le.PutUint16(buf[58:], uint16(shEntSize))
		le.PutUint16(buf[60:], 4)
		le.PutUint16(buf[62:], 3)

		p := buf[phOff:]
		le.PutUint32(p[0:], uint32(elf.PT_LOAD))
		le.PutUint32(p[4:], uint32(elf.PF_R|elf.PF_X))
		le.PutUint64(p[8:], 0)
		le.PutUint64(p[16:], 0)
		le.PutUint64(p[32:], testLoadSegmentSize)
		le.PutUint64(p[40:], testLoadSegmentSize)
	} else {
		le.PutUint16(buf[18:], uint16(elf.EM_386))
		le.PutUint32(buf[28:], phOff)
		le.PutUint32(buf[32:], shOff)
		le.PutUint16(buf[40:], uint16(ehSize))
		le.PutUint16(buf[42:], uint16(phEntSize))
		le.PutUint16(buf[44:], 1)
		le.PutUint16(buf[46:], uint16(shEntSize))
		le.PutUint16(buf[48:], 4)
		le.PutUint16(buf[50:], 3)

		p := buf[phOff:]
		le.PutUint32(p[0:], uint32(elf.PT_LOAD))
		le.PutUint32(p[4:], 0)
		le.PutUint32(p[8:], 0)
		le.PutUint32(p[16:], testLoadSegmentSize)
		le.PutUint32(p[20:], testLoadSegmentSize)
		le.PutUint32(p[24:], uint32(elf.PF_R|elf.PF_X))
	}

	copy(buf[noteOff:], note)
	copy(buf[shstrOff:], shstr)

	putSection := func(idx int, name uint32, typ elf.SectionType, addr, off, size uint32) {
		b := buf[shOff+uint32(idx)*shEntSize:]
		le.PutUint32(b[0:], name)
		le.PutUint32(b[4:], uint32(typ))
		if is64 {
			le.PutUint64(b[16:], uint64(addr))
			le.PutUint64(b[24:], uint64(off))
			le.PutUint64(b[32:], uint64(size))
			le.PutUint64(b[48:], 1)
		} else {
			le.PutUint32(b[12:], addr)
			le.PutUint32(b[16:], off)
			le.PutUint32(b[20:], size)
			le.PutUint32(b[32:], 1)
		}
	}
	putSection(0, 0, elf.SHT_NULL, 0, 0, 0)
	putSection(1, offNote, elf.SHT_NOTE, 0, noteOff, uint32(len(note)))
	putSection(2, offBase, elf.SHT_PROGBITS, testStapsdtBaseAddr, baseOff, 0)
	putSection(3, offShstr, elf.SHT_STRTAB, 0, shstrOff, uint32(len(shstr)))

	return buf
}

// usdtDesc builds a stapsdt note desc holding the three address fields at the
// given word size, followed by the provider and probe names.
func usdtDesc(wordSize int, location, base, semaphore uint64, provider, probe string) []byte {
	le := binary.LittleEndian
	desc := make([]byte, 3*wordSize)
	put := func(off int, v uint64) {
		if wordSize == 8 {
			le.PutUint64(desc[off:], v)
		} else {
			le.PutUint32(desc[off:], uint32(v))
		}
	}
	put(0, location)
	put(wordSize, base)
	put(2*wordSize, semaphore)
	desc = append(desc, []byte(provider+"\x00"+probe+"\x00")...)
	return append(desc, make([]byte, alignUp(len(desc), 4)-len(desc))...)
}

func writeTestELF(t *testing.T, data []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "target.elf")
	require.NoError(t, os.WriteFile(path, data, 0o644))
	return path
}

func TestGetUsdtInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		class        elf.Class
		desc         []byte
		expectErr    bool
		expectAttach uint64
		expectSem    uint64
	}{
		{
			name:         "64bit",
			class:        elf.ELFCLASS64,
			desc:         usdtDesc(8, 0x2000, testStapsdtBaseAddr, 0x3000, "prov", "probe"),
			expectAttach: 0x2000,
			expectSem:    0x3000,
		},
		{
			// A 32-bit binary is parsed with 4-byte address fields. Reading
			// them at a fixed 8-byte width used to panic.
			name:         "32bit",
			class:        elf.ELFCLASS32,
			desc:         usdtDesc(4, 0x2000, testStapsdtBaseAddr, 0x3000, "prov", "probe"),
			expectAttach: 0x2000,
			expectSem:    0x3000,
		},
		{
			name:         "32bit without semaphore",
			class:        elf.ELFCLASS32,
			desc:         usdtDesc(4, 0x2000, testStapsdtBaseAddr, 0, "prov", "probe"),
			expectAttach: 0x2000,
			expectSem:    0,
		},
		{
			// Regression test: the desc length guard is 3*wordSize, so a
			// 12-byte desc passes it on a 32-bit file. Reading the address
			// fields with Uint64 then read past the end of the slice and
			// panicked, killing the privileged process.
			name:      "32bit desc holding only the address fields",
			class:     elf.ELFCLASS32,
			desc:      make([]byte, 12),
			expectErr: true,
		},
		{
			name:      "64bit desc too short",
			class:     elf.ELFCLASS64,
			desc:      make([]byte, 4),
			expectErr: true,
		},
		{
			name:      "32bit desc too short",
			class:     elf.ELFCLASS32,
			desc:      make([]byte, 4),
			expectErr: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			path := writeTestELF(t, buildUsdtELF(test.class, test.desc))

			var info *usdtAttachInfo
			var err error
			require.NotPanics(t, func() {
				info, err = getUsdtInfo(path, "prov:probe")
			})

			if test.expectErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expectAttach, info.attachAddress)
			require.Equal(t, test.expectSem, info.semaphoreAddress)
		})
	}
}

func TestGetUsdtInfoRecoversPanic(t *testing.T) {
	t.Parallel()

	// A truncated ELF header makes safeelf.NewFile fail, but the parser must
	// never propagate a panic to its caller whatever the input is.
	path := writeTestELF(t, []byte{0x7f, 'E', 'L', 'F'})
	require.NotPanics(t, func() {
		_, err := getUsdtInfo(path, "prov:probe")
		require.Error(t, err)
	})
}
