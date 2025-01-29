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

// Package kallsyms provides functions to resolve kernel symbols.
package kallsyms

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"

	ebpfutils "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/ebpf"
)

var ErrAmbiguousKsym = errors.New("multiple kernel symbols with the same name")

type KAllSyms struct {
	// symbols is a slice of kernel symbols. Order is preserved.
	symbols []kernelSymbol

	// symbolsMap is a map of kernel symbols. Provides fast lookup.
	symbolsMap map[string]uint64
}

type kernelSymbol struct {
	addr uint64
	name string
}

// NewKAllSyms reads /proc/kallsyms and returns a KAllSyms.
//
// It is meant to be used when all the symbols need to be permanently loaded.
// It comes with a big resource penalty. For looking up only a few symbols, it
// is more efficient to use SymbolExists or KernelSymbolAddress.
func NewKAllSyms() (*KAllSyms, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return NewKAllSymsFromReader(file)
}

// NewKAllSymsFromReader reads a kallsyms file from the given reader and returns
// a KAllSyms.
func NewKAllSymsFromReader(reader io.Reader) (*KAllSyms, error) {
	symbols := []kernelSymbol{}
	symbolsMap := map[string]uint64{}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < 3 {
			return nil, fmt.Errorf("line %q has less than 3 fields", line)
		}

		addr, err := strconv.ParseUint(fields[0], 16, 64)
		if err != nil {
			return nil, err
		}

		// The kernel function is the third field in /proc/kallsyms line:
		// 0000000000000000 t acpi_video_unregister_backlight      [video]
		// First is the symbol address and second is described in man nm.
		symbols = append(symbols, kernelSymbol{
			addr: addr,
			name: fields[2],
		})
		symbolsMap[fields[2]] = addr
	}

	err := scanner.Err()
	if err != nil {
		return nil, err
	}

	return &KAllSyms{
		symbols:    symbols,
		symbolsMap: symbolsMap,
	}, nil
}

// LookupByInstructionPointer tries to find the kernel symbol corresponding to
// the given instruction pointer.
// For example, if instruction pointer is 0x1004 and there is a symbol which
// address is 0x1000, this function will return the name of this symbol.
// If no symbol is found, it returns "[unknown]".
func (k *KAllSyms) LookupByInstructionPointer(ip uint64) string {
	// Go translation of iovisor/bcc ksyms__map_addr():
	// https://github.com/iovisor/bcc/blob/c65446b765c9f7df7e357ee9343192de8419234a/libbpf-tools/trace_helpers.c#L149
	end := len(k.symbols) - 1
	var symAddr uint64
	start := 0

	// find largest symAddr <= ip using binary search
	for start < end {
		mid := start + (end-start+1)/2

		symAddr = k.symbols[mid].addr

		if symAddr <= ip {
			start = mid
		} else {
			end = mid - 1
		}
	}

	if start == end && k.symbols[start].addr <= ip {
		return k.symbols[start].name
	}

	return "[unknown]"
}

// SymbolExists returns true if the given symbol exists in the kernel.
func SymbolExists(symbol string) bool {
	_, _, err := KernelSymbolAddress(symbol)
	return err == nil
}

// KernelSymbolAddress looks up a symbol from /proc/kallsyms.
//
// symbol: the symbol to lookup
//
// Returns the address of the symbol and its module if any
func KernelSymbolAddress(symbol string) (uint64, string, error) {
	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return 0, "", err
	}
	defer file.Close()

	return kernelSymbolAddressFromReader(file, symbol)
}

// kernelSymbolAddressFromReader looks up a symbol from the reader.
//
// reader: source; it should be in the same file format as /proc/kallsyms
// symbol: the symbol to lookup
//
// Returns the address of the symbol and its module if any
func kernelSymbolAddressFromReader(r io.Reader, symbol string) (uint64, string, error) {
	var (
		count int
		addr  uint64
		mod   string
		err   error
	)

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		// Lines looks like:
		// ffffffff906e97e0 T security_bprm_check
		// ffffffffc1cb5010 T netem_module_init    [sch_netem]

		line := scanner.Bytes()
		typeIdx := bytes.IndexByte(line, byte(' '))
		if typeIdx == -1 || typeIdx+1 >= len(line) {
			return 0, "", fmt.Errorf("parsing line %q: no type", line)
		}
		nameIdx := bytes.IndexByte(line[typeIdx+1:], byte(' '))
		if nameIdx == -1 || typeIdx+1+nameIdx+1 >= len(line) {
			return 0, "", fmt.Errorf("parsing line %q: no symbol", line)
		}
		modIdx := bytes.IndexByte(line[typeIdx+1+nameIdx+1:], byte('\t'))
		var nameBytes []byte
		if modIdx == -1 {
			// no module
			nameBytes = line[typeIdx+1+nameIdx+1:]
		} else {
			// module found
			nameBytes = line[typeIdx+1+nameIdx+1 : typeIdx+1+nameIdx+1+modIdx]
		}
		if !bytes.Equal([]byte(symbol), nameBytes) {
			continue
		}

		addr, err = strconv.ParseUint(string(line[:typeIdx]), 16, 64)
		if err != nil {
			return 0, "", fmt.Errorf("parsing line %q: invalid address: %w", line, err)
		}
		if modIdx != -1 {
			mod = string(line[typeIdx+1+nameIdx+1+modIdx+1:])
			mod = strings.Trim(mod, "[]")
		}
		count++
		if count > 1 {
			break
		}
	}

	if err = scanner.Err(); err != nil {
		return 0, "", fmt.Errorf("reading kallsyms: %w", err)
	}

	switch count {
	case 0:
		return 0, "", os.ErrNotExist
	case 1:
		return addr, mod, nil
	default:
		// Multiple addresses for a symbol have been found. Like libbpf
		// and cilium/ebpf, reject referring to ambiguous symbols.
		return 0, "", fmt.Errorf("symbol %s: duplicate found at address 0x%x: %w",
			symbol, addr, ErrAmbiguousKsym)
	}
}

var (
	addrLock sync.Mutex

	symbolsMap   = map[string]uint64{}
	triedGetAddr = map[string]error{}
)

// SpecUpdateAddresses updates the addresses of the given symbols in the given
// collection spec.
//
// The ebpf program is expected to be have global variables with the suffix
// "_addr" for each symbol:
//
//	const volatile __u64 socket_file_ops_addr = 0;
//
// Then, SpecUpdateAddresses() can be called in this way:
//
//	kallsyms.SpecUpdateAddresses(spec, []string{"socket_file_ops"})
func SpecUpdateAddresses(spec *ebpf.CollectionSpec, symbols []string) error {
	if len(symbols) == 0 {
		// Nothing to do
		return nil
	}

	return specUpdateAddresses(
		[]symbolResolver{
			newKAllSymsResolver(),
			newEbpfResolver(),
		},
		spec,
		symbols,
	)
}

func specUpdateAddresses(
	symbolResolvers []symbolResolver,
	spec *ebpf.CollectionSpec,
	symbols []string,
) error {
	addrLock.Lock()
	defer addrLock.Unlock()

	// Are all the requested symbols in the cache?
	allFoundInCache := true
	for _, symbol := range symbols {
		if _, ok := symbolsMap[symbol]; !ok {
			if err, errFound := triedGetAddr[symbol]; errFound {
				// We previously tried to find this symbol in the cache and failed.
				return err
			}
			allFoundInCache = false
			break
		}
	}

	// Add the symbols that are not in the cache to the cache
	if !allFoundInCache {
		for _, symbol := range symbols {
			err := os.ErrNotExist
			var addr uint64
			for _, resolver := range symbolResolvers {
				addr, err = resolver.resolve(symbol)
				if err == nil {
					symbolsMap[symbol] = addr
					break
				}
			}
			if err != nil {
				triedGetAddr[symbol] = err
				return err
			}
		}
	}

	// Rewrite the constants using symbol addresses from the cache
	consts := map[string]interface{}{}
	for _, symbol := range symbols {
		consts[symbol+"_addr"] = symbolsMap[symbol]
	}
	if err := ebpfutils.SpecSetVars(spec, consts); err != nil {
		return err
	}

	return nil
}
