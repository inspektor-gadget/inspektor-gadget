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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
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

func (s *Symbolizer) resolveWithSymtab(task Task, stackItems []StackItemQuery, res []StackItemResponse) error {
	key := exeKey{task.Ino, task.MtimeSec, task.MtimeNsec}
	s.lockSymbolTables.RLock()
	table, ok := s.symbolTables[key]
	if ok {
		s.resolveStackItemsWithTable(table, stackItems, res)
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

	s.resolveStackItemsWithTable(table, stackItems, res)

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
