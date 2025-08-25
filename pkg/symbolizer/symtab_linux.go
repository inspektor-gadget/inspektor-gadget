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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
		var baseAddress uint64
		if table.isPIE {
			baseAddress, err = getBaseAddress(pid)
			if err != nil {
				return fmt.Errorf("getting base address for %q: %w", task.Name, err)
			}
		}

		s.resolveStackItemsWithTable(table, baseAddress, stackItems, res)
		s.lockSymbolTables.RUnlock()
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

	var baseAddress uint64
	if table.isPIE {
		baseAddress, err = getBaseAddress(pid)
		if err != nil {
			return fmt.Errorf("getting base address for %q: %w", task.Name, err)
		}
	}
	s.resolveStackItemsWithTable(table, baseAddress, stackItems, res)

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
		if !strings.HasPrefix(filePath, "/") {
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

	return 0, fmt.Errorf("main executable not found in maps")
}
