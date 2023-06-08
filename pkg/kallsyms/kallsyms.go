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

// Package kallsyms provides functions to read /proc/kallsyms.
package kallsyms

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
)

type KAllSyms struct {
	// symbols is a slice of kernel symbols. Order is preserved.
	symbols []kernelSymbol

	// symbolsMap is a map of kernel symbols. Provides fast lookup.
	symbolsMap map[string]uint64

	// addrMap is a map of kernel addresses. Provides fast lookup.
	addrMap map[uint64]string
}

type kernelSymbol struct {
	addr uint64
	name string
}

// NewKAllSyms reads /proc/kallsyms and returns a KAllSyms.
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
	addrMap := map[uint64]string{}

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
		addrMap[addr] = fields[2]
	}

	err := scanner.Err()
	if err != nil {
		return nil, err
	}

	return &KAllSyms{
		symbols:    symbols,
		symbolsMap: symbolsMap,
		addrMap:    addrMap,
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

// LookupByAddress tries to find the kernel symbol corresponding to the given
// address.
func (k *KAllSyms) LookupByAddress(addr uint64) string {
	name, ok := k.addrMap[addr]
	if !ok {
		return "unknown"
	}
	return name
}

// SymbolExists returns true if the given symbol exists in the kernel.
func (k *KAllSyms) SymbolExists(symbol string) bool {
	_, ok := k.symbolsMap[symbol]
	return ok
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
	kAllSymsFactory := NewKAllSyms
	return specUpdateAddresses(kAllSymsFactory, spec, symbols)
}

func specUpdateAddresses(
	kAllSymsFactory func() (*KAllSyms, error),
	spec *ebpf.CollectionSpec,
	symbols []string,
) error {
	if len(symbols) == 0 {
		// Nothing to do
		return nil
	}

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
		k, err := kAllSymsFactory()
		if err != nil {
			triedGetAddr[symbols[0]] = err
			return err
		}
		for _, symbol := range symbols {
			if _, ok := k.symbolsMap[symbol]; ok {
				symbolsMap[symbol] = k.symbolsMap[symbol]
			} else {
				triedGetAddr[symbol] = os.ErrNotExist
				fmt.Printf("symbol %q not found in kallsyms\n", symbol)
				return os.ErrNotExist
			}
		}
	}

	// Rewrite the constants using symbol addresses from the cache
	consts := map[string]interface{}{}
	for _, symbol := range symbols {
		consts[symbol+"_addr"] = symbolsMap[symbol]
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	return nil
}
