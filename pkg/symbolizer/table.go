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
	maxExecutableSize   = 512 * 1024 * 1024 // 512MB
	maxSymbolLength     = 256
	maxSymbolCount      = 10 * 1000 * 1000
	maxSymbolCountTotal = 50 * 1000 * 1000
)

func (s *Symbolizer) resolveStackItemsWithTable(table *symbolTable, baseAddress uint64, stackQueries []StackItemQuery, res []StackItemResponse) {
	table.timestamp = time.Now()
	for idx := range stackQueries {
		symbol := table.lookupByAddr(stackQueries[idx].Addr - baseAddress)
		if symbol != "" {
			res[idx].Found = true
			res[idx].Symbol = symbol
		}
	}
}

// lookupByAddr returns the symbol name for the given address.
func (e *symbolTable) lookupByAddr(address uint64) string {
	// Similar to a trivial binary search, but each symbol is a range.
	n, found := slices.BinarySearchFunc(e.symbols, address, func(a *symbol, b uint64) int {
		if a.value <= b && a.value+a.size > b {
			return 0
		}
		if a.value > b {
			return 1
		}
		if a.value < b {
			return -1
		}
		return 0
	})
	if found {
		return e.symbols[n].name
	}
	return "[unknown]"
}

func (s *Symbolizer) newSymbolTableFromFile(file *os.File) (*symbolTable, error) {
	var symbols []*symbol

	elfFile, err := elf.NewFile(file)
	if err != nil {
		return nil, fmt.Errorf("parsing ELF file: %w", err)
	}
	defer elfFile.Close()

	symtab, err := elfFile.Symbols()
	if err != nil {
		// No symbols found. This is not an error.
		return &symbolTable{}, nil
	}

	symbolCount := 0
	for _, sym := range symtab {
		if sym.Name == "" {
			continue
		}
		if sym.Size == 0 {
			continue
		}
		if len(sym.Name) > maxSymbolLength {
			sym.Name = sym.Name[:maxSymbolLength]
		}
		symbols = append(symbols, &symbol{
			name:  sym.Name,
			value: sym.Value,
			size:  sym.Size,
		})
		symbolCount++
	}
	if symbolCount > maxSymbolCount {
		return nil, fmt.Errorf("too many symbols: %d", symbolCount)
	}
	slices.SortFunc(symbols, func(a, b *symbol) int {
		if a.value < b.value {
			return -1
		}
		if a.value > b.value {
			return 1
		}
		return 0
	})

	return &symbolTable{
		symbols:   symbols,
		isPIE:     elfFile.Type == elf.ET_DYN,
		timestamp: time.Now(),
	}, nil
}
