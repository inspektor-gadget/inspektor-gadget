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

// Package symbolizer parses ELF programs and resolves stack addresses to
// symbol names.
package symbolizer

import (
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
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
	symbolTableTTL      = time.Minute
	pruneTickerTime     = time.Minute
)

var defaultDebuginfodCachePath string

func init() {
	cacheDir, err := os.UserCacheDir()
	if err != nil {
		defaultDebuginfodCachePath = "/root/.cache/debuginfod_client"
		return
	}
	defaultDebuginfodCachePath = filepath.Join(cacheDir, "debuginfod_client")
}

type SymbolizerOptions struct {
	UseSymtab                bool
	UseDebugInfodClientCache bool
	DebuginfodCachePath      string
}

type Symbolizer struct {
	options SymbolizerOptions

	lockSymbolTables sync.RWMutex
	symbolTables     map[exeKey]*symbolTable
	symbolCountTotal int

	lockSymbolTablesFromBuildID sync.RWMutex
	symbolTablesFromBuildID     map[string]*symbolTable

	// hostProcFsPidNs is the pid namespace of /host/proc/1/ns/pid.
	hostProcFsPidNs uint32

	pruneLoopStarted bool
	pruneTickerTime  time.Duration
	symbolTableTTL   time.Duration
	exit             chan struct{}
}

// symbolTable is a cache of symbols for a specific executable.
type symbolTable struct {
	// symbols is a slice of symbols. Order is preserved for binary search.
	symbols []*symbol

	timestamp time.Time
}

type symbol struct {
	name        string
	value, size uint64
}

// exeKey is an unique key for an executable given inode and mtime.
// This key is used to cache symbol tables.
type exeKey struct {
	ino       uint64
	mtimeSec  int64
	mtimeNsec uint32
}

func (k exeKey) String() string {
	return fmt.Sprintf("ino=%d mtime=%d.%d", k.ino, k.mtimeSec, k.mtimeNsec)
}

func NewSymbolizer(opts SymbolizerOptions) (*Symbolizer, error) {
	pid1PidNsInfo, err := os.Stat(fmt.Sprintf("%s/1/ns/pid", host.HostProcFs))
	if err != nil {
		return nil, err
	}
	pid1PidNsStat, ok := pid1PidNsInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("reading inode of %s/1/ns/pid", host.HostProcFs)
	}

	if opts.DebuginfodCachePath == "" {
		opts.DebuginfodCachePath = defaultDebuginfodCachePath
	}
	s := &Symbolizer{
		options:                 opts,
		symbolTables:            make(map[exeKey]*symbolTable),
		symbolTablesFromBuildID: make(map[string]*symbolTable),
		hostProcFsPidNs:         uint32(pid1PidNsStat.Ino),
		pruneTickerTime:         pruneTickerTime,
		symbolTableTTL:          symbolTableTTL,
		exit:                    make(chan struct{}),
	}
	return s, nil
}

func (s *Symbolizer) Close() {
	close(s.exit)
}

func (s *Symbolizer) pruneLoop() {
	ticker := time.NewTicker(s.pruneTickerTime)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			s.pruneOldObjects()
		case <-s.exit:
			return
		}
	}
}

func (s *Symbolizer) pruneOldObjects() {
	now := time.Now()

	// Clean symbolTables
	s.lockSymbolTables.Lock()
	tableRemovedCount := 0
	symbolRemovedCount := 0
	for key, table := range s.symbolTables {
		if now.Sub(table.timestamp) > s.symbolTableTTL {
			s.symbolCountTotal -= len(table.symbols)
			delete(s.symbolTables, key)
			tableRemovedCount++
			symbolRemovedCount += len(table.symbols)
		}
	}
	if tableRemovedCount > 0 {
		log.Debugf("symbol tables pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables with %d symbols)",
			tableRemovedCount, symbolRemovedCount,
			len(s.symbolTables), s.symbolCountTotal)
	}
	s.lockSymbolTables.Unlock()

	// Clean symbolTablesFromBuildID
	s.lockSymbolTablesFromBuildID.Lock()
	buildIDRemovedCount := 0
	buildIDSymbolRemovedCount := 0
	for buildID, table := range s.symbolTablesFromBuildID {
		if now.Sub(table.timestamp) > s.symbolTableTTL {
			delete(s.symbolTablesFromBuildID, buildID)
			buildIDRemovedCount++
			buildIDSymbolRemovedCount += len(table.symbols)
		}
	}
	if buildIDRemovedCount > 0 {
		log.Debugf("symbol tables from build ID pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables with %d symbols)",
			buildIDRemovedCount, buildIDSymbolRemovedCount,
			len(s.symbolTablesFromBuildID), s.symbolCountTotal)
	}
	s.lockSymbolTablesFromBuildID.Unlock()
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
	return ""
}

type PidNumbers struct {
	Pid     uint32
	PidNsId uint32
}

type Task struct {
	// Pids of the process that we want to resolve symbols for.
	PidNumbers []PidNumbers

	// Name of the task for logging purposes. Optional.
	Name string

	// ContainerPid is the pid 1 of the container that the process is in. Optional.
	ContainerPid uint32

	// Properties of the executable to check if the symbol table is still valid.
	Ino       uint64
	MtimeSec  int64
	MtimeNsec uint32
}

// StackItemQuery is one item of the stack. It contains the data found from BPF:
// the address and the build id. The build id comes from struct
// bpf_stack_build_id from the Linux UAPI:
// https://github.com/torvalds/linux/blob/v6.14/include/uapi/linux/bpf.h#L1451
type StackItemQuery struct {
	Addr         uint64
	ValidBuildID bool
	BuildID      [20]byte
	Offset       uint64
	IP           uint64
}

type StackItemResponse struct {
	Found  bool
	Symbol string
}

func (s *Symbolizer) Resolve(task Task, stackQueries []StackItemQuery) ([]StackItemResponse, error) {
	if len(stackQueries) == 0 {
		return nil, nil
	}
	res := make([]StackItemResponse, len(stackQueries))

	if s.options.UseSymtab {
		err := s.resolveWithSymtab(task, stackQueries, res)
		if err != nil {
			return nil, err
		}
	}
	if s.options.UseDebugInfodClientCache {
		err := s.resolveWithDebuginfodClientCache(task, stackQueries, res)
		if err != nil {
			return nil, err
		}
	}

	// Most gadgets won't use the symbolizer, so don't start the prune loop until we need it.
	if !s.pruneLoopStarted && (s.options.UseSymtab || s.options.UseDebugInfodClientCache) {
		count := 0

		s.lockSymbolTables.RLock()
		count += len(s.symbolTables)
		s.lockSymbolTables.RUnlock()

		s.lockSymbolTablesFromBuildID.RLock()
		count += len(s.symbolTablesFromBuildID)
		s.lockSymbolTablesFromBuildID.RUnlock()

		if count > 0 {
			s.pruneLoopStarted = true
			go s.pruneLoop()
		}
	}

	return res, nil
}

func (s *Symbolizer) resolveStackItemsWithTable(table *symbolTable, stackQueries []StackItemQuery, res []StackItemResponse) {
	table.timestamp = time.Now()
	for idx := range stackQueries {
		symbol := table.lookupByAddr(stackQueries[idx].Addr)
		if symbol != "" {
			res[idx].Found = true
			res[idx].Symbol = symbol
		}
	}
}

func (s *Symbolizer) resolveWithSymtab(task Task, stackQueries []StackItemQuery, res []StackItemResponse) error {
	key := exeKey{task.Ino, task.MtimeSec, task.MtimeNsec}
	s.lockSymbolTables.RLock()
	table, ok := s.symbolTables[key]
	if ok {
		s.resolveStackItemsWithTable(table, stackQueries, res)
		s.lockSymbolTables.RUnlock()
		return nil
	}
	s.lockSymbolTables.RUnlock()

	var err error
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

	s.resolveStackItemsWithTable(table, stackQueries, res)

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
		timestamp: time.Now(),
	}, nil
}

func (s *Symbolizer) resolveWithDebuginfodClientCache(task Task, stackQueries []StackItemQuery, res []StackItemResponse) error {
	for i, query := range stackQueries {
		if !query.ValidBuildID {
			continue
		}

		buildIDStr := hex.EncodeToString(query.BuildID[:])

		s.lockSymbolTablesFromBuildID.RLock()
		table, ok := s.symbolTablesFromBuildID[buildIDStr]
		if ok {
			table.timestamp = time.Now()
			symbol := table.lookupByAddr(stackQueries[i].Offset)
			if symbol != "" {
				res[i].Found = true
				res[i].Symbol = symbol
			}
			s.lockSymbolTablesFromBuildID.RUnlock()
			continue
		}
		s.lockSymbolTablesFromBuildID.RUnlock()

		debuginfoPath := filepath.Join(s.options.DebuginfodCachePath, buildIDStr, "debuginfo")
		file, err := os.Open(debuginfoPath)
		if err != nil {
			if os.IsNotExist(err) {
				suggestedCmd := fmt.Sprintf("DEBUGINFOD_CACHE_PATH=%s DEBUGINFOD_URLS=https://debuginfod.elfutils.org debuginfod-find debuginfo %s",
					s.options.DebuginfodCachePath, buildIDStr)
				log.Warnf("Debuginfo %s for %s not found in %s. Suggested remedial: %q", buildIDStr, task.Name, debuginfoPath, suggestedCmd)
				continue
			}
			log.Warnf("Failed to open debuginfo file %s for %s: %v", debuginfoPath, task.Name, err)
			continue
		}
		defer file.Close()

		// Check if the file is empty
		if fi, err := file.Stat(); err != nil {
			log.Warnf("Failed to stat debuginfo file %s: %v", debuginfoPath, err)
			continue
		} else if fi.Size() == 0 {
			suggestedCmd := fmt.Sprintf("rm -f %s", debuginfoPath)
			log.Warnf("Debuginfo %s for %s in %s is empty. Suggested remedial: %q", buildIDStr, task.Name, debuginfoPath, suggestedCmd)
			continue
		}

		table, err = s.newSymbolTableFromFile(file)
		if err != nil {
			return err
		}

		s.lockSymbolTablesFromBuildID.Lock()

		s.symbolTablesFromBuildID[buildIDStr] = table

		table.timestamp = time.Now()
		symbol := table.lookupByAddr(stackQueries[i].Offset)
		if symbol != "" {
			res[i].Found = true
			res[i].Symbol = symbol
		}
		s.lockSymbolTablesFromBuildID.Unlock()
	}

	return nil
}
