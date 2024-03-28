package uprobetracer

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/pkg/errors"
)

const (
	sdtNoteSec = ".note.stapsdt"
	sdtBaseSec = ".stapsdt.base"
)

type sectionHeader struct {
	Namesz, Descsz int32
	Type           [4]byte
}

type usdtEntry struct {
}

func getUsdtEntry(filepath string, name string) (*usdtEntry, error) {
	file, err := os.Open(filepath)
	if err != nil {
		return nil, fmt.Errorf("opening file %q: %q", filepath, err.Error())
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat file %q: %q", filepath, err.Error())
	}
	if fileInfo.Mode()&os.ModeNamedPipe != 0 {
		return nil, fmt.Errorf("ELF file %q is a pipe", filepath)
	}

	elfReader, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("reading elf file %q: %q", filepath, err.Error())
	}
	defer elfReader.Close()

	noteSection := elfReader.Section(sdtNoteSec)
	if noteSection == nil {
		return nil, errors.New("getting USDT note section")
	}

	baseSection := elfReader.Section(sdtBaseSec)
	if baseSection == nil {
		return nil, errors.New("getting USDT base section")
	}

	wordSize := 4
	if elfReader.Class == elf.ELFCLASS64 {
		wordSize = 8
	}

	notesReader := noteSection.Open()

	// sectionHeader
	// sectionName (len = hdr.Namesz)
	// sectionDesc (len = hdr.Descsz)
	//   location
	//   base
	//   semaphore
	//
	for {
		var hdr sectionHeader

		err = binary.Read(notesReader, elfReader.ByteOrder, &hdr)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, fmt.Errorf("read USDT notes: %q", err)
		}

		_, err = notesReader.Seek(int64(hdr.Namesz), io.SeekCurrent)
		if err != nil {
			return nil, fmt.Errorf("seek USDT notes: %q", err)
		}

		desc := make([]byte, hdr.Descsz)
		err = binary.Read(notesReader, binary.NativeEndian, &desc)
		if err != nil {
			return nil, fmt.Errorf("read USDT notes: %q", err)
		}

		elfLocation := elfReader.ByteOrder.Uint64(desc[:wordSize])
		elfBase := elfReader.ByteOrder.Uint64(desc[wordSize : 2*wordSize])
		elfSemaphore := elfReader.ByteOrder.Uint64(desc[2*wordSize : 3*wordSize])

		diff := baseSection.Addr - elfBase
		location := locationOffset(elfReader, elfLocation+diff)
		if elfSemaphore != 0 {
			semaphoreOffsetKernel := semaphoreOffsetKernel(elfReader, elfSemaphore+diff)
		}

		idx := 3 * wordSize
		providersz := bytes.IndexByte(desc[idx:], 0)
		provider := string(desc[idx : idx+providersz])

		idx += providersz + 1
		probesz := bytes.IndexByte(desc[idx:], 0)
		probe := string(desc[idx : idx+probesz])

	}
}

func locationOffset(f *elf.File, addr uint64) uint64 {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off
		}
	}
	return addr
}

func semaphoreOffsetKernel(f *elf.File, addr uint64) uint64 {
	sec := f.Section(probesSec)
	if sec != nil {
		return addr - sec.Addr + sec.Offset
	}
	return addr
}

func getUsdtInfo() (uint64, uint64, error) {

}
