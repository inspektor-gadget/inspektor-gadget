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
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/symbolizer"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

// getRuntimeBaseAddr gets the runtime base address of the main executable from /proc/pid/maps
func getRuntimeBaseAddr(task symbolizer.Task, table *symbolizer.SymbolTable, pid uint32) (uint64, error) {
	key := symbolizer.BaseAddrCacheKey{
		TgidLevel0:   task.Tgid,
		BaseAddrHash: task.BaseAddrHash,
	}
	if runtimeBaseAddr := table.RuntimeBaseAddrCache[key]; runtimeBaseAddr != 0 {
		log.Debugf("getRuntimeBaseAddr: pid %d (%s) runtime base address: 0x%x (from cache)",
			pid, task.Name, runtimeBaseAddr)
		return runtimeBaseAddr, nil
	}

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

		log.Debugf("getRuntimeBaseAddr: pid %d (%s) runtime base address: 0x%x (from /proc/%d/maps)",
			pid, task.Name, base, pid)
		table.RuntimeBaseAddrCache[key] = base
		return base, nil
	}

	if err := sc.Err(); err != nil {
		return 0, fmt.Errorf("reading maps file: %w", err)
	}

	// /proc/pid/maps might be empty if the process is exiting / zombie.
	return 0, fmt.Errorf("main executable not found in maps")
}
