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

package stats

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// CPUStats represents CPU statistics at a point in time
type CPUStats struct {
	User    uint64
	Nice    uint64
	System  uint64
	Idle    uint64
	IOWait  uint64
	IRQ     uint64
	SoftIRQ uint64
	Steal   uint64
}

func (m *statsRecorder) getSystemCPU() (float64, error) {
	currStats, err := readCPUStats()
	if err != nil {
		return 0.0, fmt.Errorf("read CPU stats %w", err)
	}

	usage := calculateCPUUsage(m.prevCPUStats, currStats)
	m.prevCPUStats = currStats

	return usage, nil
}

// readCPUStats reads CPU statistics from /proc/stat
func readCPUStats() (*CPUStats, error) {
	file, err := os.Open("/proc/stat")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	if !scanner.Scan() {
		return nil, fmt.Errorf("read first line from /proc/stat")
	}

	line := scanner.Text()
	fields := strings.Fields(line)
	if len(fields) < 8 || fields[0] != "cpu" {
		return nil, fmt.Errorf("invalid /proc/stat format")
	}

	stats := &CPUStats{}
	values := []*uint64{
		&stats.User,
		&stats.Nice,
		&stats.System,
		&stats.Idle,
		&stats.IOWait,
		&stats.IRQ,
		&stats.SoftIRQ,
		&stats.Steal,
	}

	for i, field := range fields[1:9] {
		val, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("parse CPU stat field %d: %w", i, err)
		}
		*values[i] = val
	}

	return stats, nil
}

// calculateCPUUsage calculates CPU usage percentage between two stat readings
func calculateCPUUsage(prev, curr *CPUStats) float64 {
	prevIdle := prev.Idle + prev.IOWait
	currIdle := curr.Idle + curr.IOWait

	prevNonIdle := prev.User + prev.Nice + prev.System + prev.IRQ + prev.SoftIRQ + prev.Steal
	currNonIdle := curr.User + curr.Nice + curr.System + curr.IRQ + curr.SoftIRQ + curr.Steal

	prevTotal := prevIdle + prevNonIdle
	currTotal := currIdle + currNonIdle

	totalDiff := currTotal - prevTotal
	idleDiff := currIdle - prevIdle

	if totalDiff == 0 {
		return 0.0
	}

	return (float64(totalDiff-idleDiff) / float64(totalDiff)) * 100.0
}
