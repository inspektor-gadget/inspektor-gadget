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

package symtab

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

func init() {
	symbolizer.RegisterResolver(&symtabResolver{})
}

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

type symtabResolver struct{}

func (s *symtabResolver) NewInstance(options symbolizer.SymbolizerOptions) (symbolizer.ResolverInstance, error) {
	if !options.UseSymtab {
		return nil, nil
	}
	hostProcFsPidNs, err := getHostProcFsPidNs()
	if err != nil {
		return nil, err
	}
	return &symtabResolverInstance{
		options:         options,
		hostProcFsPidNs: hostProcFsPidNs,
		symbolTables:    make(map[symbolizer.SymbolTableKey]*symbolizer.SymbolTable),
	}, nil
}

func (s *symtabResolver) Priority() int {
	return 0
}

type symtabResolverInstance struct {
	options symbolizer.SymbolizerOptions

	// hostProcFsPidNs is the pid namespace of /host/proc/1/ns/pid.
	hostProcFsPidNs uint32

	lockSymbolTables sync.RWMutex
	symbolTables     map[symbolizer.SymbolTableKey]*symbolizer.SymbolTable
	symbolCountTotal int
}

func (s *symtabResolverInstance) IsPruningNeeded() bool {
	s.lockSymbolTables.Lock()
	defer s.lockSymbolTables.Unlock()

	return len(s.symbolTables) > 0
}

func (s *symtabResolverInstance) PruneOldObjects(now time.Time, ttl time.Duration) {
	s.lockSymbolTables.Lock()
	tableRemovedCount := 0
	symbolRemovedCount := 0
	for key, table := range s.symbolTables {
		if now.Sub(table.Timestamp) > ttl {
			s.symbolCountTotal -= len(table.Symbols)
			delete(s.symbolTables, key)
			tableRemovedCount++
			symbolRemovedCount += len(table.Symbols)
		}
	}
	if tableRemovedCount > 0 {
		log.Debugf("symbol tables pruned: %d symbol tables with %d symbols removed (remaining: %d symbol tables with %d symbols)",
			tableRemovedCount, symbolRemovedCount,
			len(s.symbolTables), s.symbolCountTotal)
	}
	s.lockSymbolTables.Unlock()
}

func (s *symtabResolverInstance) Resolve(task symbolizer.Task, stackQueries []symbolizer.StackItemQuery, stackResponses []symbolizer.StackItemResponse) error {
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
	s.lockSymbolTables.RLock()
	table, ok := s.symbolTables[task.Exe]
	if ok {
		err = s.resolveStackItemsWithTable(task, table, pid, stackQueries, stackResponses)
		s.lockSymbolTables.RUnlock()
		if err != nil {
			return fmt.Errorf("resolving stack for %q: %w", task.Name, err)
		}
		return nil
	}
	s.lockSymbolTables.RUnlock()

	table, err = newSymbolTableFromPid(pid, task.Exe)
	if err != nil {
		return fmt.Errorf("creating new symbolTable for %q: %w", task.Name, err)
	}

	s.lockSymbolTables.Lock()
	defer s.lockSymbolTables.Unlock()
	if len(table.Symbols)+s.symbolCountTotal > symbolizer.MaxSymbolCountTotal {
		return fmt.Errorf("too many symbols in all symbol tables: %d (max: %d)",
			len(table.Symbols)+s.symbolCountTotal, symbolizer.MaxSymbolCountTotal)
	}

	s.symbolTables[task.Exe] = table
	s.symbolCountTotal += len(table.Symbols)

	log.Debugf("symbol table for %q (pid %d) loaded: %d symbols (total: %d symbol tables with %d symbols)",
		task.Name, pid, len(table.Symbols), len(s.symbolTables), s.symbolCountTotal)

	err = s.resolveStackItemsWithTable(task, table, pid, stackQueries, stackResponses)
	if err != nil {
		return fmt.Errorf("resolving stack for %q: %w", task.Name, err)
	}

	return nil
}

// symbolTableKeyFromFile computes a key for the symbol table from the
// executable's inode and modification time.
func symbolTableKeyFromFile(file *os.File) (*symbolizer.SymbolTableKey, error) {
	fs, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat process executable: %w", err)
	}
	stat, ok := fs.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, errors.New("getting syscall.Stat_t failed")
	}

	if fs.Size() > symbolizer.MaxExecutableSize {
		return nil, fmt.Errorf("executable is too large (%d bytes)", fs.Size())
	}

	return &symbolizer.SymbolTableKey{
		Major:     unix.Major(stat.Dev),
		Minor:     unix.Minor(stat.Dev),
		Ino:       stat.Ino,
		MtimeSec:  stat.Mtim.Sec,
		MtimeNsec: uint32(stat.Mtim.Nsec),
	}, nil
}

func newSymbolTableFromPid(pid uint32, symbolTableKeyFromEbpf symbolizer.SymbolTableKey) (*symbolizer.SymbolTable, error) {
	path := fmt.Sprintf("%s/%d/exe", host.HostProcFs, pid)
	file, err := os.Open(path)
	if err != nil {
		// The process might have terminated, or it might be in an unreachable
		// pid namespace. Either way, we can't resolve symbols.
		return nil, fmt.Errorf("opening process executable: %w", err)
	}
	defer file.Close()
	expectedSymbolTableKey, err := symbolTableKeyFromFile(file)
	if err != nil {
		return nil, err
	}
	if *expectedSymbolTableKey != symbolTableKeyFromEbpf {
		newComm, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", file.Fd()))
		newComm = filepath.Base(newComm)
		return nil, fmt.Errorf("opening executable: got %q inode %d, mtime %d.%d (expected inode %d, mtime%d.%d)",
			newComm, expectedSymbolTableKey.Ino,
			expectedSymbolTableKey.MtimeSec, expectedSymbolTableKey.MtimeNsec,
			symbolTableKeyFromEbpf.Ino,
			symbolTableKeyFromEbpf.MtimeSec, symbolTableKeyFromEbpf.MtimeNsec)
	}

	return symbolizer.NewSymbolTableFromFile(file)
}

func (s *symtabResolverInstance) resolveStackItemsWithTable(task symbolizer.Task, table *symbolizer.SymbolTable, pid uint32, stackQueries []symbolizer.StackItemQuery, res []symbolizer.StackItemResponse) error {
	table.Timestamp = time.Now()

	var runtimeBaseAddr uint64
	var err error

	runtimeBaseAddr, err = getRuntimeBaseAddr(task, table, pid)
	if err != nil {
		return fmt.Errorf("getting runtime base address: %w", err)
	}

	log.Debugf("resolving %d stack frames with symbol table (pid %d, PIE=%v): runtime base address 0x%x, elf base address 0x%x, bias %d",
		len(stackQueries), pid, table.IsPIE,
		runtimeBaseAddr, table.ElfBaseAddr,
		int64(table.ElfBaseAddr-runtimeBaseAddr))

	for idx := range stackQueries {
		symbol := table.LookupByAddr(stackQueries[idx].Addr - runtimeBaseAddr + table.ElfBaseAddr)
		if symbol != "" {
			res[idx].Found = true
			res[idx].Symbol = symbol
		}
	}
	return nil
}
