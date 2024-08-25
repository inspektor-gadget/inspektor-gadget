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
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"
)

// For details regarding the data format of USDT notes, please refer to:
// https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
const (
	sdtNoteSectionName = ".note.stapsdt"
	sdtBaseSectionName = ".stapsdt.base"
)

// sync with usdt_helper.bpf.c
const (
	// name of map for storing arguments info used in the eBPF part
	UsdtArgsInfoMapName = "__usdt_args_info"
	// name of per-cpu buffer map, used for communication between exetnsion and user program
	UsdtArgsBufferMapName = "__usdt_args_buffer"
	usdtArgsMaxCount      = 12
	// name of function that will be replaced by ebpf extension
	usdtArgsRewriteFuncName = "__usdt_get_argument"
	// magic number for verifying the integrity of arguments info
	usdtArgsMagic = uint64(0xA)
)

// sync with usdt_helper.bpf.c
const (
	usdtArgsLengthUnsigned8 = iota
	usdtArgsLengthSigned8
	usdtArgsLengthUnsigned16
	usdtArgsLengthSigned16
	usdtArgsLengthUnsigned32
	usdtArgsLengthSigned32
	usdtArgsLengthUnsigned64
	usdtArgsLengthSigned64
)

var (
	patternArgumentRegister = regexp.MustCompile("^%([a-z][a-z0-9]+)$")
	patternArgumentMemory   = regexp.MustCompile("^(-?\\d+)\\(%([a-z0-9]+)\\)$")

	usdtCookieUUID        atomic.Uint64
	usdtArgsInfoMap       *ebpf.Map
	usdtArgsInfoMapOnce   sync.Once
	usdtArgsBufferMap     *ebpf.Map
	usdtArgsBufferMapOnce sync.Once
	usdtExtensionSpec     *ebpf.CollectionSpec
	usdtExtensionSpecOnce sync.Once
)

type noteHeader struct {
	NameSize uint32
	DescSize uint32
	Type     uint32
}

type usdtAttachInfo struct {
	attachAddresses    []uint64
	semaphoreAddresses []uint64
	arguments          []*[usdtArgsMaxCount]uint64
}

func vaddr2ElfOffset(f *elf.File, addr uint64) (uint64, error) {
	for _, prog := range f.Progs {
		if prog.Vaddr <= addr && addr < (prog.Vaddr+prog.Memsz) {
			return addr - prog.Vaddr + prog.Off, nil
		}
	}
	return 0, fmt.Errorf("malformed elf file: elf prog containing addr %x not found", addr)
}

func alignUp[T int | int32 | int64 | uint | uint32 | uint64](n T, align T) T {
	return (n + align - 1) / align * align
}

func encodeArgument(arg string) (uint64, error) {
	/**
	 * support the following patterns:
	 * <size>@%<reg>
	 * <size>@<offset>(%<reg>)
	 */

	// encode field value into the output with given offset,
	// the `fieldOffset` and `fieldLength` should be given in bits.
	encodeField := func(encodedValue *uint64, fieldOffset uint, fieldLength uint, fieldValue uint64) {
		*encodedValue |= (fieldValue & (1<<(fieldLength+1) - 1)) << fieldOffset
	}

	parts := strings.Split(arg, "@")
	if len(parts) != 2 {
		return 0, fmt.Errorf("invalid usdt argument format: %q", arg)
	}

	/**
	 * unsigned version : 4
	 * enum USDT_ARG_TYPE type : 1
	 * enum USDT_ARG_LENGTH length : 3
	 * enum USDT_ARG_REG reg : 8
	 * int offset : 16
	 * unsigned _padding : 32
	 */

	// encode argument version
	encodedValue := uint64(0)
	encodeField(&encodedValue, 0, 4, usdtArgsMagic)

	// encode argument length
	argLength, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid length field in usdt argument: %q", parts[0])
	}
	// the following values 1/-1 etc. are part of USDT standards, see `Argument Format` section in
	// https://sourceware.org/systemtap/wiki/UserSpaceProbeImplementation
	switch argLength {
	case 1:
		argLength = usdtArgsLengthUnsigned8
	case -1:
		argLength = usdtArgsLengthSigned8
	case 2:
		argLength = usdtArgsLengthUnsigned16
	case -2:
		argLength = usdtArgsLengthSigned16
	case 4:
		argLength = usdtArgsLengthUnsigned32
	case -4:
		argLength = usdtArgsLengthSigned32
	case 8:
		argLength = usdtArgsLengthUnsigned64
	case -8:
		argLength = usdtArgsLengthSigned64
	default:
		return 0, fmt.Errorf("unsupported length for usdt argument: %q", argLength)
	}
	encodeField(&encodedValue, 5, 3, uint64(argLength))

	encodeRegister := func(encodedValue *uint64, regName string) error {
		encoding, exist := registerEncoding[regName]
		if !exist {
			return fmt.Errorf("unsupported register: %q", regName)
		}
		encodeField(encodedValue, 8, 8, encoding)
		return nil
	}

	if matches := patternArgumentRegister.FindStringSubmatch(parts[1]); matches != nil {
		if err := encodeRegister(&encodedValue, matches[1]); err != nil {
			return 0, err
		}
	} else if matches = patternArgumentMemory.FindStringSubmatch(parts[1]); matches != nil {
		// memory argument
		encodeField(&encodedValue, 4, 1, 1)

		if err := encodeRegister(&encodedValue, matches[2]); err != nil {
			return 0, err
		}

		offsetStr := matches[1]
		if offsetValue, err := strconv.ParseInt(offsetStr, 10, 16); err == nil {
			encodeField(&encodedValue, 16, 16, uint64(offsetValue))
		} else {
			return 0, fmt.Errorf("unsupported memory offset: %q", offsetStr)
		}
	} else {
		return 0, fmt.Errorf("unsupported usdt argument type: %q", parts[1])
	}

	return encodedValue, nil
}

func (t *Tracer[Event]) getUsdtInfo(filepath string, attachSymbol string) (*usdtAttachInfo, error) {
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

	elfReader, err := elf.NewFile(file)
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
	notesReader := noteSection.Open()

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

	results := &usdtAttachInfo{}

	// walk through USDT notes, and match with providerName and probeName
	// For details of the structure of ELF notes, please refer to
	// https://man7.org/linux/man-pages/man5/elf.5.html, the `Notes (Nhdr)` section
	for {
		var header noteHeader
		err = binary.Read(notesReader, elfReader.ByteOrder, &header)
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("reading USDT note header: %w", err)
		}

		name := make([]byte, alignUp(uint64(header.NameSize), 4))
		err = binary.Read(notesReader, elfReader.ByteOrder, &name)
		if err != nil {
			return nil, fmt.Errorf("reading USDT note name: %w", err)
		}

		desc := make([]byte, alignUp(uint64(header.DescSize), 4))
		err = binary.Read(notesReader, elfReader.ByteOrder, &desc)
		if err != nil {
			return nil, fmt.Errorf("reading USDT note desc: %w", err)
		}

		if string(name) != "stapsdt\x00" || header.Type != 3 {
			continue
		}

		provider := readStringFromBytes(desc, uint32(3*wordSize))
		probe := readStringFromBytes(desc, uint32(3*wordSize+len(provider)+1))
		if provider != providerName || probe != probeName {
			continue
		}

		elfLocation := elfReader.ByteOrder.Uint64(desc[:wordSize])
		elfBase := elfReader.ByteOrder.Uint64(desc[wordSize : 2*wordSize])
		elfSemaphore := elfReader.ByteOrder.Uint64(desc[2*wordSize : 3*wordSize])

		diff := baseSection.Addr - elfBase
		location, err := vaddr2ElfOffset(elfReader, elfLocation+diff)
		if err != nil {
			return nil, err
		}

		if elfSemaphore != 0 {
			elfSemaphore, err = vaddr2ElfOffset(elfReader, elfSemaphore+diff)
			if err != nil {
				return nil, err
			}
		}

		// parse arguments
		argumentsString := readStringFromBytes(desc, uint32(3*wordSize+len(provider)+1+len(probe)+1))
		arguments := &[usdtArgsMaxCount]uint64{}
		for idx, arg := range strings.Split(argumentsString, " ") {
			arguments[idx], err = encodeArgument(arg)
			if err != nil {
				t.logger.Debugf("encoding argument %d: %s", idx, err.Error())
			}
		}

		results.attachAddresses = append(results.attachAddresses, location)
		results.semaphoreAddresses = append(results.semaphoreAddresses, elfSemaphore)
		results.arguments = append(results.arguments, arguments)
	}

	if len(results.attachAddresses) == 0 {
		return nil, errors.New("no matching USDT metadata")
	}

	return results, nil
}

func getUsdtArgsInfoMap() (*ebpf.Map, error) {
	var err error
	usdtArgsInfoMapOnce.Do(func() {
		usdtArgsInfoMapSpec := ebpf.MapSpec{
			Name:       UsdtArgsInfoMapName,
			Type:       ebpf.Hash,
			KeySize:    8,
			ValueSize:  8 * usdtArgsMaxCount,
			MaxEntries: 1024,
		}
		usdtArgsInfoMap, err = ebpf.NewMap(&usdtArgsInfoMapSpec)
	})
	if err != nil {
		return nil, fmt.Errorf("creating USDT arguments info map: %w", err)
	}
	return usdtArgsInfoMap, nil
}

func GetUsdtArgsBufferMap() (*ebpf.Map, error) {
	var err error
	usdtArgsBufferMapOnce.Do(func() {
		usdtArgsBufferMapSpec := ebpf.MapSpec{
			Name:       UsdtArgsBufferMapName,
			Type:       ebpf.PerCPUArray,
			KeySize:    4,
			ValueSize:  8,
			MaxEntries: 1,
		}
		usdtArgsBufferMap, err = ebpf.NewMap(&usdtArgsBufferMapSpec)
	})
	if err != nil {
		return nil, fmt.Errorf("creating USDT arguments buffer map: %w", err)
	}
	return usdtArgsBufferMap, nil
}

func hasUsdtArgsFunction(target *ebpf.Program) bool {
	btfHandle, err := target.Handle()
	if err != nil {
		return false
	}
	defer btfHandle.Close()

	spec, err := btfHandle.Spec(nil)
	if err != nil {
		return false
	}

	var function *btf.Func
	err = spec.TypeByName(usdtArgsRewriteFuncName, &function)
	return err == nil
}

func injectUsdtArgsExtension(target *ebpf.Program) (link.Link, error) {
	// load extension spec
	var err error
	usdtExtensionSpecOnce.Do(func() {
		usdtExtensionSpec, err = loadUsdthelper()
	})
	if err != nil {
		return nil, fmt.Errorf("loading extension spec: %w", err)
	}
	extensionSpec := usdtExtensionSpec.Copy()

	// bind attach target
	extensionProgramSpec, exist := extensionSpec.Programs[usdtArgsRewriteFuncName]
	if !exist {
		return nil, errors.New("UsdtArgsExtension spec not found")
	}
	extensionProgramSpec.AttachTarget = target

	// rewrite usdtArgsMap and load extension program
	usdtArgsInfoMap, err := getUsdtArgsInfoMap()
	if err != nil {
		return nil, err
	}
	usdtArgsBufferMap, err := GetUsdtArgsBufferMap()
	if err != nil {
		return nil, err
	}
	mapReplacements := map[string]*ebpf.Map{
		UsdtArgsInfoMapName:   usdtArgsInfoMap,
		UsdtArgsBufferMapName: usdtArgsBufferMap,
	}
	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}
	collection, err := ebpf.NewCollectionWithOptions(extensionSpec, opts)
	if err != nil {
		return nil, fmt.Errorf("loading UsdtArgsExtension: %w", err)
	}
	defer collection.Close()

	extensionProgram, exist := collection.Programs[usdtArgsRewriteFuncName]
	if !exist {
		return nil, errors.New("UsdtArgsExtension program not found")
	}
	extensionLink, err := link.AttachFreplace(target, usdtArgsRewriteFuncName, extensionProgram)
	if err != nil {
		return nil, fmt.Errorf("replacing function %q: %w", usdtArgsRewriteFuncName, err)
	}

	return extensionLink, nil
}
