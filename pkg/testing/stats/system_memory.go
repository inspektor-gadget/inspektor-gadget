// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package stats

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// memoryStats represents memory statistics at a point in time
type memoryStats struct {
	MemTotal     uint64 // Total usable RAM (in kB)
	MemFree      uint64 // Amount of free RAM (in kB)
	MemAvailable uint64 // Available memory for new processes (in kB)
	Buffers      uint64 // Temporary storage for raw disk blocks (in kB)
	Cached       uint64 // In-memory cache for files read from disk (in kB)
	SReclaimable uint64 // Reclaimable slab memory (in kB)
}

func (m *statsRecorder) getSystemMemory() (uint64, error) {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, err
	}
	defer file.Close()

	stats := &memoryStats{}
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			continue
		}

		switch key {
		case "MemTotal":
			stats.MemTotal = value
		case "MemFree":
			stats.MemFree = value
		case "MemAvailable":
			stats.MemAvailable = value
		case "Buffers":
			stats.Buffers = value
		case "Cached":
			stats.Cached = value
		case "SReclaimable":
			stats.SReclaimable = value
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, err
	}

	if stats.MemTotal == 0 {
		return 0, fmt.Errorf("read MemTotal from /proc/meminfo")
	}

	// Calculate used memory more accurately
	// Available memory is a better indicator than just Free memory
	// as it accounts for reclaimable memory (buffers, cached, etc.)
	availableKB := stats.MemAvailable
	if availableKB == 0 {
		// Fallback calculation if MemAvailable is not available
		availableKB = stats.MemFree + stats.Buffers + stats.Cached + stats.SReclaimable
	}

	usedKB := stats.MemTotal - availableKB
	return usedKB * 1024, nil
}
