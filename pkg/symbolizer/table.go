// Copyright 2025 The Inspektor Gadget authors
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

package symbolizer

import (
	"debug/elf"
	"fmt"
	"os"
	"slices"
	"time"
)

const (
	MaxExecutableSize   = 512 * 1024 * 1024 // 512MB
	MaxSymbolLength     = 256
	MaxSymbolCount      = 10 * 1000 * 1000
	MaxSymbolCountTotal = 50 * 1000 * 1000
)

// LookupByAddr returns the symbol name for the given address.
func (e *SymbolTable) LookupByAddr(address uint64) string {
	// Similar to a trivial binary search, but each symbol is a range.
	n, found := slices.BinarySearchFunc(e.Symbols, address, func(a *Symbol, b uint64) int {
		if a.Value <= b && a.Value+a.Size > b {
			return 0
		}
		if a.Value > b {
			return 1
		}
		if a.Value < b {
			return -1
		}
		return 0
	})
	if found {
		return e.Symbols[n].Name
	}
	return fmt.Sprintf("[unknown:%x]", address)
}

func NewSymbolTableFromFile(file *os.File) (*SymbolTable, error) {
	var symbols []*Symbol

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("parsing ELF file: %w", err)
	}
	defer elfFile.Close()

	symtab, err := elfFile.Symbols()
	if err != nil {
		// No symbols found. This is not an error.
		return &SymbolTable{
			RuntimeBaseAddrCache: make(map[BaseAddrCacheKey]uint64),
		}, nil
	}

	symbolCount := 0
	for _, sym := range symtab {
		if sym.Name == "" {
			continue
		}
		if sym.Size == 0 {
			continue
		}
		if len(sym.Name) > MaxSymbolLength {
			sym.Name = sym.Name[:MaxSymbolLength]
		}
		symbols = append(symbols, &Symbol{
			Name:  sym.Name,
			Value: sym.Value,
			Size:  sym.Size,
		})
		symbolCount++
	}
	if symbolCount > MaxSymbolCount {
		return nil, fmt.Errorf("too many symbols: %d", symbolCount)
	}
	slices.SortFunc(symbols, func(a, b *Symbol) int {
		if a.Value < b.Value {
			return -1
		}
		if a.Value > b.Value {
			return 1
		}
		return 0
	})
	// Find the virtual address of the first LOAD segment
	// Command line equivalent:
	//   readelf -lW $FILE | grep -m1 LOAD | awk '{print $3}'
	var elfBaseAddr uint64
	for _, prog := range elfFile.Progs {
		if prog.Type == elf.PT_LOAD {
			elfBaseAddr = prog.Vaddr
			break
		}
	}

	return &SymbolTable{
		Symbols:              symbols,
		IsPIE:                elfFile.Type == elf.ET_DYN,
		ElfBaseAddr:          elfBaseAddr,
		Timestamp:            time.Now(),
		RuntimeBaseAddrCache: make(map[BaseAddrCacheKey]uint64),
	}, nil
}
