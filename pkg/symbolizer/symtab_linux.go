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

//go:build linux

package symbolizer

import (
	"bufio"
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	maxExecutableSize   = 512 * 1024 * 1024 // 512MB
	maxSymbolLength     = 256
	maxSymbolCount      = 10 * 1000 * 1000
	maxSymbolCountTotal = 50 * 1000 * 1000
)

func getHostProcFsPidNs() (uint32, error) {
	pid1PidNsInfo, err := os.Stat(fmt.Sprintf("%s/1/ns/pid", host.HostProcFs))
	if err != nil {
		return 0, err
	}
	pid1PidNsStat, ok := pid1PidNsInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, fmt.Errorf("reading inode of %s/1/ns/pid", host.HostProcFs)
	}
	return uint32(pid1PidNsStat.Ino), nil
}

func (s *Symbolizer) resolveWithSymtab(task Task, stackQueries []StackItemQuery, res []StackItemResponse) error {
	pid := uint32(0)
	for _, pidnr := range task.PidNumbers {
		if pidnr.PidNsId == s.hostProcFsPidNs {
			pid = pidnr.Pid
			break
		}
	}
	if pid == 0 {
		return fmt.Errorf("procfs for %q not found", task.Name)
	}

	var err error
	key := exeKey{task.Ino, task.MtimeSec, task.MtimeNsec}
	s.lockSymbolTables.RLock()
	table, ok := s.symbolTables[key]
	if ok {
		err = s.resolveStackItemsWithTable(table, pid, stackQueries, res)
		s.lockSymbolTables.RUnlock()
		if err != nil {
			return fmt.Errorf("resolving stack for %q: %w", task.Name, err)
		}
		return nil
	}
	s.lockSymbolTables.RUnlock()

	table, err = s.newSymbolTableFromPid(pid, key)
	if err != nil {
		return fmt.Errorf("creating new symbolTable for %q: %w", task.Name, err)
	}

	s.lockSymbolTables.Lock()
	defer s.lockSymbolTables.Unlock()
	if len(table.symbols)+s.symbolCountTotal > maxSymbolCountTotal {
		return fmt.Errorf("too many symbols in all symbol tables: %d (max: %d)",
			len(table.symbols)+s.symbolCountTotal, maxSymbolCountTotal)
	}

	s.symbolTables[key] = table
	s.symbolCountTotal += len(table.symbols)

	log.Debugf("symbol table for %q (pid %d) loaded: %d symbols (total: %d symbol tables with %d symbols)",
		task.Name, pid, len(table.symbols), len(s.symbolTables), s.symbolCountTotal)

	err = s.resolveStackItemsWithTable(table, pid, stackQueries, res)
	if err != nil {
		return fmt.Errorf("resolving stack for %q: %w", task.Name, err)
	}

	return nil
}

func (s *Symbolizer) newSymbolTableFromPid(pid uint32, expectedExeKey exeKey) (*symbolTable, error) {
	path := fmt.Sprintf("%s/%d/exe", host.HostProcFs, pid)
	file, err := os.Open(path)
	if err != nil {
		// The process might have terminated, or it might be in an unreachable
		// pid namespace. Either way, we can't resolve symbols.
		return nil, fmt.Errorf("opening process executable: %w", err)
	}
	defer file.Close()
	fs, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat process executable: %w", err)
	}
	stat, ok := fs.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("getting syscall.Stat_t failed")
	}
	ino := stat.Ino
	newKey := exeKey{ino, stat.Mtim.Sec, uint32(stat.Mtim.Nsec)}
	if newKey != expectedExeKey {
		newComm, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
		newComm = filepath.Base(newComm)
		return nil, fmt.Errorf("opening executable: got %q inode %d, mtime %d.%d (expected %s)",
			newComm, ino, stat.Mtim.Sec, stat.Mtim.Nsec,
			expectedExeKey)
	}
	if fs.Size() > maxExecutableSize {
		return nil, fmt.Errorf("executable is too large (%d bytes)", fs.Size())
	}

	return s.newSymbolTableFromFile(file)
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

func (s *Symbolizer) resolveStackItemsWithTable(table *symbolTable, pid uint32, stackQueries []StackItemQuery, res []StackItemResponse) error {
	table.timestamp = time.Now()

	var baseAddress uint64
	var err error
	if table.isPIE {
		baseAddress, err = getBaseAddress(pid)
		if err != nil {
			return fmt.Errorf("getting base address: %w", err)
		}
	}

	for idx := range stackQueries {
		symbol := table.lookupByAddr(stackQueries[idx].Addr - baseAddress)
		if symbol != "" {
			res[idx].Found = true
			res[idx].Symbol = symbol
		}
	}
	return nil
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

// getBaseAddress gets the runtime base address of the main executable from /proc/pid/maps
func getBaseAddress(pid uint32) (uint64, error) {
	mapsPath := filepath.Join(host.HostProcFs, fmt.Sprint(pid), "maps")
	f, err := os.Open(mapsPath)
	if err != nil {
		return 0, fmt.Errorf("opening maps file: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		parts := strings.Fields(line)
		if len(parts) <= 5 {
			continue
		}
		// Only check "r--p" (read-only) and "r-xp" (executable) sections as these
		// reliably belong to the main executable, not heap/stack/anonymous memory.
		perms := parts[1]
		if perms != "r--p" && perms != "r-xp" {
			continue
		}
		// Check if this is the main executable (not heap/vdso/anonymous)
		filePath := parts[5]
		if len(filePath) == 0 || filePath[0] != '/' {
			continue
		}
		// Find the lowest address mapping for the main executable (ASLR base address).
		addrRange := parts[0]
		rangeParts := strings.Split(addrRange, "-")
		baseStr := strings.TrimSpace(rangeParts[0])
		base, err := strconv.ParseUint(baseStr, 16, 64)
		if err != nil {
			continue
		}
		return base, nil
	}

	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("reading maps file: %w", err)
	}

	// /proc/pid/maps might be empty if the process is exiting / zombie.
	return 0, fmt.Errorf("main executable not found in maps")
}
